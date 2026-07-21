// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

// doctorRepo builds a temp repo with an in-tree policy + registries enrolling a
// freshly generated SSH key for alex@example.com, git-configured for SSH signing
// with that key. attestationEnroll controls whether the same key is also enrolled
// in attestation_signers (to exercise the ADR-040 distinctness check).
func doctorRepo(t *testing.T, metaPaths, attestationEnroll string) (repo string, keyPath string) {
	t.Helper()
	repo = t.TempDir()
	run := func(args ...string) {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "alex@example.com")
	run("config", "user.name", "Alex")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	keyPath = filepath.Join(t.TempDir(), "commit.pub") // outside the repo, like ~/.ssh
	if err := os.WriteFile(keyPath, ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		t.Fatal(err)
	}
	run("config", "gpg.format", "ssh")
	run("config", "user.signingkey", keyPath)

	line, err := sshsig.FormatEnrollmentLine("alex@example.com", "git", pub)
	if err != nil {
		t.Fatal(err)
	}
	write := func(rel, content string) {
		p := filepath.Join(repo, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".semver-trust/policy.toml", `[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [`+metaPaths+`]
required_level = "T3"

[identity]
attestation_signers = ".semver-trust/attestation_signers"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"

[identity.agent]
bot_accounts = ["ci-bot@example.com"]
`)
	write(".semver-trust/allowed_signers", line+"\n")
	att := ""
	if attestationEnroll == "same" {
		attLine, _ := sshsig.FormatEnrollmentLine("alex@example.com", "attestation@semver-trust.dev", pub)
		att = attLine + "\n"
	}
	write(".semver-trust/attestation_signers", att)

	run("add", ".")
	run("-c", "commit.gpgsign=false", "commit", "-q", "-m", "adopt")
	return repo, keyPath
}

func envFor(t *testing.T, repo string, persona Persona) *Env {
	t.Helper()
	raw, _ := os.ReadFile(filepath.Join(repo, ".semver-trust", "policy.toml"))
	pol, perr := policy.Parse(raw)
	git, err := LoadGitConfig(repo)
	if err != nil {
		t.Fatal(err)
	}
	return &Env{
		Repo: repo, Persona: persona, At: time.Now(),
		Policy: pol, PolicyRaw: raw, PolicyPath: ".semver-trust/policy.toml", PolicyErr: perr, Git: git,
	}
}

func TestKeysChecks(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**", ".github/workflows/**"`, "distinct")
	env := envFor(t, repo, Maintainer)

	if r := checkSigningKeyLoads(env); r.Severity != PASS {
		t.Errorf("signing-key-loads = %s %q, want PASS", r.Severity, r.Message)
	}
	if r := checkAttestationDistinct(env); r.Severity != PASS {
		t.Errorf("attestation-distinct (distinct key) = %s %q, want PASS", r.Severity, r.Message)
	}

	// The same key enrolled as both commit and attestation signer is a FAIL (ADR-040).
	repo2, _ := doctorRepo(t, `".semver-trust/**"`, "same")
	if r := checkAttestationDistinct(envFor(t, repo2, Maintainer)); r.Severity != FAIL {
		t.Errorf("attestation-distinct (shared key) = %s, want FAIL", r.Severity)
	}

	// A declared-but-unreadable attestation registry must fail closed, not PASS
	// (the one check enforcing ADR-040 distinctness).
	repo3, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")
	if err := os.Remove(filepath.Join(repo3, ".semver-trust", "attestation_signers")); err != nil {
		t.Fatal(err)
	}
	if r := checkAttestationDistinct(envFor(t, repo3, Maintainer)); r.Severity != FAIL {
		t.Errorf("attestation-distinct (unreadable registry) = %s, want FAIL (fail closed)", r.Severity)
	}
}

func TestRegistryChecks(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// alex is enrolled → PASS for maintainer.
	if r := checkPrincipalEnrolled(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("principal-enrolled = %s %q, want PASS", r.Severity, r.Message)
	}
	// ci-bot bot account is not enrolled → WARN.
	if r := checkBotAccounts(envFor(t, repo, Maintainer)); r.Severity != WARN {
		t.Errorf("bot-accounts = %s %q, want WARN", r.Severity, r.Message)
	}
	// no gpg_keyring declared → SKIP.
	if r := checkGPGKeyring(envFor(t, repo, Maintainer)); r.Severity != SKIP {
		t.Errorf("gpg-keyring = %s, want SKIP (none declared)", r.Severity)
	}
}

func TestPolicyChecks(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	// meta covers .semver-trust/** and .github/workflows/** → coverage PASS.
	full := envFor(t, mustRepo(t, `".semver-trust/**", ".github/workflows/**"`), Maintainer)
	if r := checkMetaCoverage(full); r.Severity != PASS {
		t.Errorf("meta-coverage (full) = %s %q, want PASS", r.Severity, r.Message)
	}
	// meta missing .github/workflows/** → the CI path is uncovered → WARN.
	partial := envFor(t, mustRepo(t, `".semver-trust/**"`), Maintainer)
	if r := checkMetaCoverage(partial); r.Severity != WARN {
		t.Errorf("meta-coverage (partial) = %s %q, want WARN", r.Severity, r.Message)
	}
	// no adoption boundary declared → SKIP.
	if r := checkAdoptionBoundary(full); r.Severity != SKIP {
		t.Errorf("adoption-boundary = %s, want SKIP (none declared)", r.Severity)
	}
}

func mustRepo(t *testing.T, metaPaths string) string {
	t.Helper()
	repo, _ := doctorRepo(t, metaPaths, "distinct")
	return repo
}

func TestSimulateClassify(t *testing.T) {
	env := &Env{Persona: Maintainer, At: time.Now()}

	// A message whose final paragraph is a valid Provenance trailer → PASS.
	env.Message = []byte("subject line\n\nbody\n\nProvenance: human\n")
	if r := checkSimulateClassify(env); r.Severity != PASS {
		t.Errorf("classify (good) = %s %q, want PASS", r.Severity, r.Message)
	}

	// A message that mentions Provenance but not as the final paragraph → the
	// silent-floor trap → FAIL.
	env.Message = []byte("subject\n\nProvenance: human\n\nmore body after the trailer\n")
	if r := checkSimulateClassify(env); r.Severity != FAIL {
		t.Errorf("classify (misplaced trailer) = %s %q, want FAIL", r.Severity, r.Message)
	}

	// No message → SKIP.
	env.Message = nil
	if r := checkSimulateClassify(env); r.Severity != SKIP {
		t.Errorf("classify (none) = %s, want SKIP", r.Severity)
	}
}

func TestSimulateCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")
	env := envFor(t, repo, Maintainer)

	// The adopt commit is unsigned → simulate/commit surfaces the signature abort,
	// the same *verify.AbortError the real pipeline emits (the drift guard).
	env.Commit = "HEAD"
	r := checkSimulateCommit(env)
	if r.Severity != FAIL {
		t.Errorf("simulate/commit on unsigned HEAD = %s %q, want FAIL", r.Severity, r.Message)
	}
	if !strings.Contains(r.Preempts, "step 3") {
		t.Errorf("simulate/commit should preempt the §10 step-3 signature abort; Preempts=%q", r.Preempts)
	}

	// no --commit → SKIP.
	env.Commit = ""
	if r := checkSimulateCommit(env); r.Severity != SKIP {
		t.Errorf("simulate/commit without --commit = %s, want SKIP", r.Severity)
	}
}
