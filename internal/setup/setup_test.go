// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/gitconfig"
)

// sshEnv is a clean SSH-mode Env: a fresh clone (all managed keys unset), a normal
// euid, no include/GIT_DIR/bare hazards.
func sshEnv() Env {
	return Env{
		Config:     &gitconfig.Config{GitPath: "/usr/bin/git"},
		SigningKey: "/home/alex/.ssh/commit.pub",
		Remote:     "origin",
		Euid:       501,
	}
}

// localCurrents reads the repo-LOCAL value of every managed key — what the PR-C
// command populates Env.Current with, so a global/included value never leaks in.
func localCurrents(t *testing.T, git gitconfig.Git) map[string]string {
	t.Helper()
	cur := map[string]string{}
	for _, k := range []string{keyGPGFormat, keySigningKey, keyCommitGPGSign, keyCommitTemplate, keyAllowedSigners} {
		v, err := git.GetLocal(k)
		if err != nil {
			t.Fatalf("GetLocal %s: %v", k, err)
		}
		cur[k] = v
	}
	return cur
}

func actionOf(p *Plan, key string) Action {
	for _, c := range p.Changes {
		if c.Key == key {
			return c.Action
		}
	}
	return ""
}

func TestPlanFreshSSH(t *testing.T) {
	p, err := Compute(sshEnv())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// gpg.format, user.signingkey, commit.gpgsign all set; no gitmessage/registry.
	if len(p.Changes) != 3 {
		t.Fatalf("changes = %d, want 3: %+v", len(p.Changes), p.Changes)
	}
	for _, k := range []string{keyGPGFormat, keySigningKey, keyCommitGPGSign} {
		if a := actionOf(p, k); a != ActionSet {
			t.Errorf("%s action = %q, want set", k, a)
		}
	}
	if actionOf(p, keyGPGFormat) != ActionSet {
		t.Error("gpg.format")
	}
	// The attestation refspec would be appended (not yet present).
	if p.Fetch == nil || p.Fetch.Already || p.Fetch.Refspec != AttestationRefspec {
		t.Errorf("fetch = %+v, want a pending non-force attestation refspec", p.Fetch)
	}
}

func TestPlanGitmessageAndRegistry(t *testing.T) {
	env := sshEnv()
	env.GitmessageExists = true
	env.AllowedSignersExists = true
	env.AllowedSignersPath = ".semver-trust/allowed_signers"
	p, err := Compute(env)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if actionOf(p, keyCommitTemplate) != ActionSet {
		t.Error("commit.template should be managed when .gitmessage exists")
	}
	if actionOf(p, keyAllowedSigners) != ActionSet {
		t.Error("gpg.ssh.allowedSignersFile should be managed in SSH mode when the file exists")
	}
}

func TestPlanIdempotent(t *testing.T) {
	env := sshEnv()
	env.Current = map[string]string{
		keyGPGFormat:     "ssh",
		keySigningKey:    "/home/alex/.ssh/commit.pub",
		keyCommitGPGSign: "true",
	}
	env.RemoteFetchRefspecs = []string{"+refs/attestations/*:refs/attestations/*"} // a +-variant
	p, err := Compute(env)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, c := range p.Changes {
		if c.Action != ActionOK {
			t.Errorf("%s = %q, want ok (already set)", c.Key, c.Action)
		}
	}
	if p.Fetch == nil || !p.Fetch.Already {
		t.Errorf("an equivalent +-variant refspec must be idempotent: %+v", p.Fetch)
	}
}

func TestPlanConflictRefusedThenForced(t *testing.T) {
	env := sshEnv()
	env.Current = map[string]string{keyGPGFormat: "openpgp"} // conflicts with the desired ssh
	if _, err := Compute(env); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("a gpg.format conflict without --force must refuse: %v", err)
	}
	env.Force = true
	p, err := Compute(env)
	if err != nil {
		t.Fatalf("--force should proceed: %v", err)
	}
	if actionOf(p, keyGPGFormat) != ActionForced {
		t.Errorf("gpg.format under --force = %q, want forced", actionOf(p, keyGPGFormat))
	}
}

func TestPlanNeverForcesSigningKey(t *testing.T) {
	env := sshEnv()
	env.Current = map[string]string{keySigningKey: "/home/alex/.ssh/OLD.pub"} // a different, already-set local signing key
	env.Force = true                                                          // even with --force
	_, err := Compute(env)
	if err == nil {
		t.Fatal("a user.signingkey conflict must refuse even with --force (SU-11)")
	}
	if strings.Contains(err.Error(), "--force") {
		t.Errorf("the signing-key refusal must never suggest --force: %q", err)
	}
	if !strings.Contains(err.Error(), "signing identity") {
		t.Errorf("unexpected message: %q", err)
	}
}

func TestPlanEnvironmentRefusals(t *testing.T) {
	root := sshEnv()
	root.Euid = 0
	if _, err := Compute(root); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("euid 0 must refuse: %v", err)
	}

	gitdir := sshEnv()
	gitdir.GitDirEnv = true
	if _, err := Compute(gitdir); err == nil || !strings.Contains(err.Error(), "GIT_DIR") {
		t.Errorf("GIT_DIR env must refuse: %v", err)
	}

	bare := sshEnv()
	bare.Config.Bare = true
	if _, err := Compute(bare); err == nil || !strings.Contains(err.Error(), "bare") {
		t.Errorf("a bare repo must refuse: %v", err)
	}

	neither := sshEnv()
	neither.SigningKey = ""
	if _, err := Compute(neither); err == nil {
		t.Error("no signing mode must refuse")
	}
}

func TestPlanCrossCheck(t *testing.T) {
	// The offered signing key is also an attestation key → ADR-040 refusal.
	env := sshEnv()
	env.SigningKeyFingerprint = "SHA256:abc"
	env.AttestationSignersDeclared = true
	env.AttestationFingerprints = []string{"SHA256:abc"}
	if _, err := Compute(env); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Errorf("a signing key present in attestation_signers must refuse: %v", err)
	}

	// A declared-but-unreadable attestation registry fails closed.
	env2 := sshEnv()
	env2.SigningKeyFingerprint = "SHA256:xyz"
	env2.AttestationSignersDeclared = true
	env2.AttestationReadErr = errors.New("permission denied")
	if _, err := Compute(env2); err == nil || !strings.Contains(err.Error(), "distinctness") {
		t.Errorf("an unreadable attestation registry must fail closed: %v", err)
	}

	// A declared registry with an EMPTY offered-key fingerprint (the boundary
	// key-load failed) must also fail closed — never a silent bypass.
	env3 := sshEnv()
	env3.SigningKeyFingerprint = ""
	env3.AttestationSignersDeclared = true
	env3.AttestationFingerprints = []string{"SHA256:someone"}
	if _, err := Compute(env3); err == nil || !strings.Contains(err.Error(), "distinctness") {
		t.Errorf("an unfingerprintable signing key must fail closed, not bypass: %v", err)
	}
}

// All-or-nothing: a signing-key conflict AND another conflict must be reported
// together in one refusal (the signing-key conflict must not hide the rest).
func TestPlanCombinedConflicts(t *testing.T) {
	env := sshEnv()
	env.Current = map[string]string{
		keySigningKey: "/home/alex/.ssh/OLD.pub", // force-immune conflict
		keyGPGFormat:  "openpgp",                 // a forceable conflict
	}
	// No --force: both are conflicts and BOTH must appear in the single refusal.
	_, err := Compute(env)
	if err == nil {
		t.Fatal("a combined conflict must refuse")
	}
	if !strings.Contains(err.Error(), keySigningKey) {
		t.Errorf("refusal must list the signing-key conflict:\n%s", err)
	}
	if !strings.Contains(err.Error(), keyGPGFormat) {
		t.Errorf("all-or-nothing: refusal must ALSO list the gpg.format conflict:\n%s", err)
	}
}

func TestPlanIncludeDowngrade(t *testing.T) {
	env := sshEnv()
	env.Config.HasIncludes = true
	p, err := Compute(env)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(p.Warnings) == 0 {
		t.Error("an include environment should disclose a caveat")
	}
	// Unset keys are downgraded to manual (emit the command, don't auto-write).
	if actionOf(p, keyGPGFormat) != ActionManual {
		t.Errorf("under includes, an unset key = %q, want manual", actionOf(p, keyGPGFormat))
	}
}

func TestPlanGPGMode(t *testing.T) {
	env := Env{Config: &gitconfig.Config{GitPath: "/usr/bin/git"}, GPGSigningKey: "ABCD1234", Remote: "origin", Euid: 501}
	p, err := Compute(env)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, c := range p.Changes {
		if c.Key == keyGPGFormat && c.Desired != "openpgp" {
			t.Errorf("GPG mode gpg.format = %q, want openpgp", c.Desired)
		}
		if c.Key == keySigningKey && c.Desired != "ABCD1234" {
			t.Errorf("GPG mode user.signingkey = %q, want the key id", c.Desired)
		}
	}
	// No allowedSignersFile in GPG mode.
	if actionOf(p, keyAllowedSigners) != "" {
		t.Error("GPG mode must not manage gpg.ssh.allowedSignersFile")
	}
}

func TestApply(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "a@b.c"}, {"config", "user.name", "A"}} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	cfg, err := gitconfig.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	git := gitconfig.Git{Path: cfg.GitPath, Repo: repo}
	env := Env{Config: cfg, Current: localCurrents(t, git), SigningKey: "/keys/commit.pub", Remote: "origin", Euid: 501}
	p, err := Compute(env)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if err := p.Apply(git); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// The writes round-trip through a fresh read.
	reload, _ := gitconfig.Load(repo)
	if reload.GPGFormat != "ssh" || reload.SigningKey != "/keys/commit.pub" || reload.CommitGPGSign != "true" {
		t.Errorf("after Apply: format=%q key=%q sign=%q", reload.GPGFormat, reload.SigningKey, reload.CommitGPGSign)
	}
	specs, _ := gitconfig.Git{Path: cfg.GitPath, Repo: repo}.FetchRefspecs("origin")
	if len(specs) != 1 || specs[0] != AttestationRefspec {
		t.Errorf("fetch refspecs = %v, want the attestation refspec", specs)
	}

	// Re-planning against the now-configured repo is fully idempotent.
	cfg2, _ := gitconfig.Load(repo)
	git2 := gitconfig.Git{Path: cfg2.GitPath, Repo: repo}
	specs2, _ := git2.FetchRefspecs("origin")
	p2, err := Compute(Env{Config: cfg2, Current: localCurrents(t, git2), SigningKey: "/keys/commit.pub", Remote: "origin", Euid: 501, RemoteFetchRefspecs: specs2})
	if err != nil {
		t.Fatalf("re-Plan: %v", err)
	}
	for _, c := range p2.Changes {
		if c.Action != ActionOK {
			t.Errorf("re-run %s = %q, want ok", c.Key, c.Action)
		}
	}
	if !p2.Fetch.Already {
		t.Error("re-run refspec should be already-set")
	}
}

func TestReverseAndGitCommands(t *testing.T) {
	env := sshEnv()
	env.Current = map[string]string{keyGPGFormat: "openpgp"}
	env.Force = true // gpg.format becomes a forced change
	p, err := Compute(env)
	if err != nil {
		t.Fatal(err)
	}
	rev := strings.Join(p.ReverseCommands(), "\n")
	// A forced key's reversal restores the OLD value; a newly-set key is unset.
	if !strings.Contains(rev, `git config gpg.format "openpgp"`) {
		t.Errorf("forced-change reversal should restore the old value:\n%s", rev)
	}
	if !strings.Contains(rev, "git config --unset user.signingkey") {
		t.Errorf("newly-set key reversal should --unset:\n%s", rev)
	}
	cmds := strings.Join(p.GitCommands(), "\n")
	if !strings.Contains(cmds, "git config --add remote.origin.fetch") {
		t.Errorf("dry-run commands should include the refspec --add:\n%s", cmds)
	}
}
