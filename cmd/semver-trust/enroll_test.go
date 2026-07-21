// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

const enrollPolicyTOML = `[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T3"

[identity]
attestation_signers = ".semver-trust/attestation_signers"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"
`

// enrollRepo builds a temp repo with the enroll policy and a git identity, and
// writes a fresh SSH public key to a path outside the repo (like ~/.ssh). It
// returns the repo, the .pub path, and the parsed public key for byte-exact checks.
func enrollRepo(t *testing.T) (repo, pubPath string, pub ssh.PublicKey) {
	t.Helper()
	repo = t.TempDir()
	gitCLI(t, repo, "init", "-q")
	gitCLI(t, repo, "config", "user.email", "alex@example.com")
	gitCLI(t, repo, "config", "user.name", "Alex")
	doctorWriteFile(t, filepath.Join(repo, ".semver-trust", "policy.toml"), enrollPolicyTOML)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub = signer.PublicKey()
	pubPath = filepath.Join(t.TempDir(), "commit.pub")
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo, pubPath, pub
}

func TestEnrollCommand(t *testing.T) {
	repo, pubPath, pub := enrollRepo(t)
	wantLine, err := sshsig.FormatEnrollmentLine("alex@example.com", "git", pub)
	if err != nil {
		t.Fatal(err)
	}

	// Print-by-default: the byte-exact line on stdout; guidance on stderr; no write.
	out, errOut, err := runRoot(t, "enroll", "--repo", repo, "--commit-key", pubPath)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if strings.TrimRight(out, "\n") != wantLine {
		t.Errorf("stdout = %q, want the byte-exact line %q", out, wantLine)
	}
	if !strings.Contains(errOut, "alex@example.com") || !strings.Contains(errOut, "fingerprint SHA256:") {
		t.Errorf("stderr should disclose principal + fingerprint:\n%s", errOut)
	}
	if _, statErr := os.Stat(filepath.Join(repo, ".semver-trust", "allowed_signers")); !os.IsNotExist(statErr) {
		t.Error("print-by-default must not write the registry")
	}

	// --write appends atomically; the registry then parses and resolves the key.
	if _, _, err := runRoot(t, "enroll", "--repo", repo, "--commit-key", pubPath, "--write"); err != nil {
		t.Fatalf("enroll --write: %v", err)
	}
	reg, err := os.ReadFile(filepath.Join(repo, ".semver-trust", "allowed_signers"))
	if err != nil {
		t.Fatalf("registry not written: %v", err)
	}
	signers, err := sshsig.ParseAllowedSigners(reg)
	if err != nil {
		t.Fatalf("written registry does not parse: %v", err)
	}
	if _, err := sshsig.Resolve(pub, signers, "git", time.Now()); err != nil {
		t.Errorf("written registry does not resolve the key: %v", err)
	}

	// A second identical --write is a duplicate refusal.
	if _, _, err := runRoot(t, "enroll", "--repo", repo, "--commit-key", pubPath, "--write"); err == nil {
		t.Error("re-enrolling the same key should refuse (duplicate)")
	}
}

func TestEnrollCrossRegistryRefusal(t *testing.T) {
	repo, pubPath, pub := enrollRepo(t)
	// Pre-enroll the key as an ATTESTATION signer, then try to enroll it as a commit
	// key — ADR-040 two-key distinctness refuses it.
	attLine, err := sshsig.FormatEnrollmentLine("alex@example.com", "attestation@semver-trust.dev", pub)
	if err != nil {
		t.Fatal(err)
	}
	doctorWriteFile(t, filepath.Join(repo, ".semver-trust", "attestation_signers"), attLine+"\n")

	out, _, err := runRoot(t, "enroll", "--repo", repo, "--commit-key", pubPath, "--write")
	if err == nil {
		t.Fatal("a commit key already in attestation_signers must be refused (ADR-040)")
	}
	if !strings.Contains(err.Error(), "distinct") {
		t.Errorf("want the distinctness refusal, got: %v (%s)", err, out)
	}
}

// genPubFile writes a fresh SSH public key to a temp path and returns it.
func genPubFile(t *testing.T) string {
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
	return p
}

// The same key targeted at both registries in ONE invocation must be refused
// (ADR-040): each target's on-disk cross-check cannot see the other's pending
// mutation, so the distinctness guard has to also cover the pending set.
func TestEnrollRefusesSameKeyBothRegistries(t *testing.T) {
	repo, pubPath, _ := enrollRepo(t)
	allowed := filepath.Join(repo, ".semver-trust", "allowed_signers")
	att := filepath.Join(repo, ".semver-trust", "attestation_signers")

	// Print-by-default: refused by the pending-set ADR-040 check, before any write.
	if _, _, err := runRoot(t, "enroll", "--repo", repo, "--commit-key", pubPath, "--attest-key", pubPath); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Errorf("same key in both registries (print) = %v, want the ADR-040 refusal", err)
	}
	// With --write it is refused too, and nothing is written.
	if _, _, err := runRoot(t, "enroll", "--repo", repo, "--commit-key", pubPath, "--attest-key", pubPath, "--write"); err == nil {
		t.Error("same key in both registries with --write should refuse")
	}
	for _, p := range []string{allowed, att} {
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Errorf("a refused enrollment must not write %s", p)
		}
	}
}

// Multi-target --write is refused: per-file temp+rename gives no cross-file
// transaction, so the tool does one registry per --write rather than fake
// all-or-nothing. Multi-target print (no write) is fine.
func TestEnrollMultiTargetWriteRefused(t *testing.T) {
	repo, commitPub, _ := enrollRepo(t)
	attestPub := genPubFile(t)

	// Two distinct keys PRINT fine — two lines, no write.
	out, _, err := runRoot(t, "enroll", "--repo", repo, "--commit-key", commitPub, "--attest-key", attestPub)
	if err != nil {
		t.Fatalf("multi-target print: %v", err)
	}
	if n := len(strings.Split(strings.TrimSpace(out), "\n")); n != 2 {
		t.Errorf("want two printed lines, got %d:\n%s", n, out)
	}

	// Multi-target --write is refused deliberately, and writes nothing. --dry-run
	// previews the real --write, so the same restriction applies to --write --dry-run
	// AND to --dry-run alone — a preview must never advertise an operation the real
	// path would reject.
	for _, args := range [][]string{
		{"--write"},
		{"--write", "--dry-run"},
		{"--dry-run"},
	} {
		full := append([]string{"enroll", "--repo", repo, "--commit-key", commitPub, "--attest-key", attestPub}, args...)
		if _, _, werr := runRoot(t, full...); werr == nil || !strings.Contains(werr.Error(), "one registry at a time") {
			t.Errorf("multi-target %v = %v, want the one-at-a-time refusal", args, werr)
		}
	}
	if _, statErr := os.Stat(filepath.Join(repo, ".semver-trust", "allowed_signers")); !os.IsNotExist(statErr) {
		t.Error("a refused multi-target --write must not write any registry")
	}
}

func TestEnrollDryRunAndNoTarget(t *testing.T) {
	repo, pubPath, _ := enrollRepo(t)

	// --dry-run changes nothing but still prints the line + the plan.
	out, errOut, err := runRoot(t, "enroll", "--repo", repo, "--commit-key", pubPath, "--write", "--dry-run")
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if strings.TrimSpace(out) == "" {
		t.Error("dry-run should still print the line")
	}
	if !strings.Contains(errOut, "dry-run") {
		t.Errorf("dry-run should announce it modifies nothing:\n%s", errOut)
	}
	if _, statErr := os.Stat(filepath.Join(repo, ".semver-trust", "allowed_signers")); !os.IsNotExist(statErr) {
		t.Error("--dry-run must not write the registry")
	}

	// No target flag → refusal.
	if _, _, err := runRoot(t, "enroll", "--repo", repo); err == nil {
		t.Error("enroll with no --commit-key/--attest-key should refuse")
	}
}
