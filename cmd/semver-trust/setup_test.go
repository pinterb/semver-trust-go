// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

// gitLocal reads a repo-LOCAL config value (what setup writes).
func gitLocal(t *testing.T, repo, key string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "config", "--local", "--get", key).Output()
	if err != nil {
		return "" // unset
	}
	return strings.TrimSpace(string(out))
}

// genKeyFile writes a fresh SSH public key and returns its path and parsed key.
func genKeyFile(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "k.pub")
	if err := os.WriteFile(p, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, signer.PublicKey()
}

func setupRepo(t *testing.T) (repo, pub string) {
	t.Helper()
	repo = t.TempDir()
	gitCLI(t, repo, "init", "-q")
	gitCLI(t, repo, "config", "user.email", "alex@example.com")
	gitCLI(t, repo, "config", "user.name", "Alex")
	p, _ := genKeyFile(t)
	return repo, p
}

func TestSetupCommand(t *testing.T) {
	repo, pub := setupRepo(t)

	// --dry-run: the env echo + the exact git config commands; nothing is written.
	out, _, err := runRoot(t, "setup", "--repo", repo, "--signing-key", pub, "--dry-run")
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !strings.Contains(out, "setup: repo ") || !strings.Contains(out, " git ") || !strings.Contains(out, "remote origin") {
		t.Errorf("env-echo first line (repo/git/remote) missing:\n%s", out)
	}
	if !strings.Contains(out, `git config gpg.format "ssh"`) {
		t.Errorf("dry-run should print the git config commands:\n%s", out)
	}
	if gitLocal(t, repo, "gpg.format") != "" {
		t.Error("--dry-run must not write config")
	}

	// Real run: the keys are written locally, and a reversal receipt is printed.
	out2, _, err := runRoot(t, "setup", "--repo", repo, "--signing-key", pub)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if gitLocal(t, repo, "gpg.format") != "ssh" {
		t.Error("gpg.format not set to ssh")
	}
	if gitLocal(t, repo, "user.signingkey") != pub {
		t.Errorf("user.signingkey = %q, want %q", gitLocal(t, repo, "user.signingkey"), pub)
	}
	if gitLocal(t, repo, "commit.gpgsign") != "true" {
		t.Error("commit.gpgsign not set")
	}
	if !strings.Contains(out2, "to reverse") || !strings.Contains(out2, "git config --unset gpg.format") {
		t.Errorf("reversal receipt missing:\n%s", out2)
	}
	// The attestation fetch refspec was appended.
	if got := gitLocal(t, repo, "remote.origin.fetch"); !strings.Contains(got, "refs/attestations/") {
		t.Errorf("attestation fetch refspec not configured: %q", got)
	}

	// Idempotent re-run: nothing to change.
	out3, _, err := runRoot(t, "setup", "--repo", repo, "--signing-key", pub)
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if !strings.Contains(out3, "already fully configured") {
		t.Errorf("a second run should be idempotent:\n%s", out3)
	}
}

func TestSetupConflict(t *testing.T) {
	repo, pub := setupRepo(t)
	gitCLI(t, repo, "config", "gpg.format", "openpgp") // a local conflict

	if _, _, err := runRoot(t, "setup", "--repo", repo, "--signing-key", pub); err == nil {
		t.Error("a gpg.format conflict without --force must refuse")
	}
	// --force overwrites the non-identity conflict.
	if _, _, err := runRoot(t, "setup", "--repo", repo, "--signing-key", pub, "--force"); err != nil {
		t.Fatalf("--force should proceed: %v", err)
	}
	if gitLocal(t, repo, "gpg.format") != "ssh" {
		t.Error("--force should overwrite gpg.format to ssh")
	}
}

func TestSetupNeverForcesSigningKey(t *testing.T) {
	repo, pub := setupRepo(t)
	gitCLI(t, repo, "config", "user.signingkey", "/keys/OLD.pub") // a different local signing key

	_, _, err := runRoot(t, "setup", "--repo", repo, "--signing-key", pub, "--force")
	if err == nil {
		t.Error("a user.signingkey conflict must refuse even with --force")
	}
	if strings.Contains(err.Error(), "--force") {
		t.Errorf("the signing-key refusal must never suggest --force: %v", err)
	}
	if gitLocal(t, repo, "user.signingkey") != "/keys/OLD.pub" {
		t.Error("the existing signing key must be left untouched")
	}
}

func TestSetupCrossCheck(t *testing.T) {
	repo := t.TempDir()
	gitCLI(t, repo, "init", "-q")
	gitCLI(t, repo, "config", "user.email", "alex@example.com")
	gitCLI(t, repo, "config", "user.name", "Alex")
	keyPath, pub := genKeyFile(t)

	// A policy declaring attestation_signers, with the OFFERED key enrolled there.
	doctorWriteFile(t, filepath.Join(repo, ".semver-trust", "policy.toml"), enrollPolicyTOML)
	line, err := sshsig.FormatEnrollmentLine("alex@example.com", "attestation@semver-trust.dev", pub)
	if err != nil {
		t.Fatal(err)
	}
	doctorWriteFile(t, filepath.Join(repo, ".semver-trust", "attestation_signers"), line+"\n")

	_, _, err = runRoot(t, "setup", "--repo", repo, "--signing-key", keyPath)
	if err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Errorf("a signing key that is also an attestation key must refuse (ADR-022): %v", err)
	}
}

// policyWithAllowedSigners is a minimal valid policy declaring a custom
// identity.human.allowed_signers path (to exercise the fence).
func policyWithAllowedSigners(path string) string {
	return `[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T3"

[identity.human]
allowed_signers = "` + path + `"
`
}

// A PRESENT policy that cannot be loaded must be surfaced, not silently dropped
// (dropping one that declared attestation_signers would skip the ADR-022 check).
func TestSetupMalformedPolicyRefused(t *testing.T) {
	repo, pub := setupRepo(t)
	doctorWriteFile(t, filepath.Join(repo, ".semver-trust", "policy.toml"), "this is not valid toml {{{")

	_, _, err := runRoot(t, "setup", "--repo", repo, "--signing-key", pub)
	if err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("a malformed present policy must refuse: %v", err)
	}
	if gitLocal(t, repo, "gpg.format") != "" {
		t.Error("a refused run must write nothing")
	}
}

// The policy-named allowed_signers path is fenced before use — a traversing or
// symlinked value must not point local git's verification authority outside the repo.
func TestSetupFencesAllowedSignersPath(t *testing.T) {
	// Traversal.
	repo, pub := setupRepo(t)
	doctorWriteFile(t, filepath.Join(repo, ".semver-trust", "policy.toml"),
		policyWithAllowedSigners("../../outside/allowed_signers"))
	if _, _, err := runRoot(t, "setup", "--repo", repo, "--signing-key", pub); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("a traversing allowed_signers path must be refused: %v", err)
	}
	if gitLocal(t, repo, "gpg.format") != "" {
		t.Error("a refused run must write nothing")
	}

	// Symlink escaping the repo.
	repo2, pub2 := setupRepo(t)
	outside := filepath.Join(t.TempDir(), "outside_signers")
	if err := os.WriteFile(outside, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo2, ".semver-trust"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo2, ".semver-trust", "linked_signers")); err != nil {
		t.Skip("symlinks unsupported on this platform")
	}
	doctorWriteFile(t, filepath.Join(repo2, ".semver-trust", "policy.toml"),
		policyWithAllowedSigners(".semver-trust/linked_signers"))
	if _, _, err := runRoot(t, "setup", "--repo", repo2, "--signing-key", pub2); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("a symlinked allowed_signers path must be refused: %v", err)
	}
}

// The env-echo audit line is the first line of EVERY run, including refusals.
func TestSetupEnvEchoOnRefusal(t *testing.T) {
	repo, pub := setupRepo(t)
	gitCLI(t, repo, "config", "gpg.format", "openpgp") // forces a conflict refusal

	out, _, err := runRoot(t, "setup", "--repo", repo, "--signing-key", pub)
	if err == nil {
		t.Fatal("expected a conflict refusal")
	}
	if !strings.Contains(out, "setup: repo ") || !strings.Contains(out, " git ") {
		t.Errorf("the env-echo audit line must appear on stdout even on a refusal:\n%s", out)
	}
}

func TestSetupBareRefused(t *testing.T) {
	bare := t.TempDir()
	gitCLI(t, bare, "init", "--bare", "-q")
	pub, _ := genKeyFile(t)
	if _, _, err := runRoot(t, "setup", "--repo", bare, "--signing-key", pub); err == nil {
		t.Error("a bare repository must refuse")
	}
}

func TestSetupLinkedWorktree(t *testing.T) {
	main := t.TempDir()
	gitCLI(t, main, "init", "-q")
	gitCLI(t, main, "config", "user.email", "a@b.c")
	gitCLI(t, main, "config", "user.name", "A")
	doctorWriteFile(t, filepath.Join(main, "README"), "x")
	gitCLI(t, main, "add", ".")
	gitCLI(t, main, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init")

	wt := filepath.Join(t.TempDir(), "wt")
	gitCLI(t, main, "worktree", "add", "-q", wt)
	pub, _ := genKeyFile(t)

	out, _, err := runRoot(t, "setup", "--repo", wt, "--signing-key", pub)
	if err != nil {
		t.Fatalf("setup in a linked worktree should succeed: %v", err)
	}
	if !strings.Contains(out, "linked worktree") {
		t.Errorf("a linked worktree should disclose the shared-config caveat:\n%s", out)
	}
}
