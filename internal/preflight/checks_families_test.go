// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/gitconfig"
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
	// Write the private half alongside (unencrypted), so keys/sign-roundtrip has a
	// complete signing setup — a real clone has both halves under ~/.ssh.
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(strings.TrimSuffix(keyPath, ".pub"), pem.EncodeToMemory(block), 0o600); err != nil {
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
	git, err := gitconfig.Load(repo)
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
	// ci-bot bot account is not enrolled → WARN, and the fix must name both the
	// keyring option and dropping the declaration — not just allowed_signers (a
	// GPG-signing repo has no allowed_signers to enroll into, and a repo that
	// never web-UI-merges should simply drop the entry).
	if r := checkBotAccounts(envFor(t, repo, Maintainer)); r.Severity != WARN {
		t.Errorf("bot-accounts = %s %q, want WARN", r.Severity, r.Message)
	} else if !strings.Contains(r.Fix, "gpg_keyring") || !strings.Contains(r.Fix, "bot_accounts") {
		t.Errorf("bot-accounts fix should offer the keyring and drop-the-declaration options; Fix=%q", r.Fix)
	}
	// no gpg_keyring declared → SKIP.
	if r := checkGPGKeyring(envFor(t, repo, Maintainer)); r.Severity != SKIP {
		t.Errorf("gpg-keyring = %s, want SKIP (none declared)", r.Severity)
	}
}

// parseCheckRepo builds a dir with a parseable policy + allowed_signers in the
// working tree, in one of the git states the drift checks must tell apart:
//
//	"no-head"      a git repo with no commits — HEAD does not resolve
//	"file-absent"  a git repo whose seed commit omits the trust material, so HEAD
//	               resolves but the files are absent from its tree
//	"not-a-repo"   a plain directory that will not open as a git repository — a
//	               genuine tree-read error, not a fresh-bootstrap state
func parseCheckRepo(t *testing.T, state string) string {
	t.Helper()
	repo := t.TempDir()
	run := func(args ...string) {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if state != "not-a-repo" {
		run("init", "-q")
		run("config", "user.email", "alex@example.com")
		run("config", "user.name", "Alex")
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	line, err := sshsig.FormatEnrollmentLine("alex@example.com", "git", signer.PublicKey())
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
	if state == "file-absent" {
		// A seed commit that does NOT include the trust material: HEAD resolves,
		// but the policy/registry files are absent from its tree.
		write("README.md", "# widget\n")
		run("add", "README.md")
		run("-c", "commit.gpgsign=false", "commit", "-q", "-m", "init")
	}
	write(".semver-trust/policy.toml", `[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity]
attestation_signers = ".semver-trust/attestation_signers"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"

[trailers]
require = true

[graph]
adapter = "none"
`)
	write(".semver-trust/allowed_signers", line+"\n")
	return repo
}

// TestParseChecksNoCommits pins the fresh-bootstrap case: policy and registry
// parse, but with no HEAD the drift check cannot run — so the PASS message must
// not claim "matches HEAD" (nothing was compared).
func TestParseChecksNoCommits(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	env := envFor(t, parseCheckRepo(t, "no-head"), Maintainer)

	if r := checkPolicyParse(env); r.Severity != PASS {
		t.Errorf("policy/parse (no commits) = %s %q, want PASS", r.Severity, r.Message)
	} else if strings.Contains(r.Message, "matches HEAD") {
		t.Errorf("policy/parse (no commits) must not claim 'matches HEAD' — nothing was compared; Message=%q", r.Message)
	}

	if r := checkRegistryParse(env); r.Severity != PASS {
		t.Errorf("registry/parse (no commits) = %s %q, want PASS", r.Severity, r.Message)
	} else if strings.Contains(r.Message, "matches HEAD") {
		t.Errorf("registry/parse (no commits) must not claim 'matches HEAD' — nothing was compared; Message=%q", r.Message)
	}
}

// TestParseChecksHeadFileAbsent covers the other fresh-bootstrap shape: HEAD
// resolves, but the trust material is not yet in its tree. Still a legitimate
// "not yet committed" PASS — no false "matches HEAD".
func TestParseChecksHeadFileAbsent(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	env := envFor(t, parseCheckRepo(t, "file-absent"), Maintainer)

	if r := checkPolicyParse(env); r.Severity != PASS {
		t.Errorf("policy/parse (file absent from HEAD) = %s %q, want PASS", r.Severity, r.Message)
	} else if strings.Contains(r.Message, "matches HEAD") {
		t.Errorf("policy/parse (file absent from HEAD) must not claim 'matches HEAD'; Message=%q", r.Message)
	}

	if r := checkRegistryParse(env); r.Severity != PASS {
		t.Errorf("registry/parse (file absent from HEAD) = %s %q, want PASS", r.Severity, r.Message)
	} else if strings.Contains(r.Message, "matches HEAD") {
		t.Errorf("registry/parse (file absent from HEAD) must not claim 'matches HEAD'; Message=%q", r.Message)
	}
}

// TestParseChecksTreeReadError pins the non-bootstrap error path: when the HEAD
// tree read fails for a real reason (here, the dir is not a git repository), the
// checks must WARN that the comparison could not run — never PASS, which would
// falsely advertise a fresh-repo state or a clean match.
func TestParseChecksTreeReadError(t *testing.T) {
	repo := parseCheckRepo(t, "not-a-repo")
	raw, err := os.ReadFile(filepath.Join(repo, ".semver-trust", "policy.toml"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	env := &Env{
		Repo: repo, Persona: Maintainer, At: time.Now(),
		Policy: pol, PolicyRaw: raw, PolicyPath: ".semver-trust/policy.toml",
	}

	if r := checkPolicyParse(env); r.Severity != WARN {
		t.Errorf("policy/parse (tree-read error) = %s %q, want WARN", r.Severity, r.Message)
	}
	if r := checkRegistryParse(env); r.Severity != WARN {
		t.Errorf("registry/parse (tree-read error) = %s %q, want WARN", r.Severity, r.Message)
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
