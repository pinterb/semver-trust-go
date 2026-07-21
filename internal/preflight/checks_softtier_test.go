// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/chain"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

// stage writes rel under the repo and adds it to the index, so the --staged
// simulate checks see it.
func stage(t *testing.T, repo, rel, content string) {
	t.Helper()
	p := filepath.Join(repo, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", repo, "add", rel).CombinedOutput(); err != nil {
		t.Fatalf("git add %s: %v\n%s", rel, err, out)
	}
}

func TestConfiguredVsEnrolled(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	// The doctorRepo signing key is enrolled for alex@example.com → PASS.
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")
	if r := checkConfiguredVsEnrolled(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("configured-vs-enrolled (enrolled) = %s %q, want PASS", r.Severity, r.Message)
	}
}

func TestSignRoundtrip(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	// doctorRepo now writes the private half alongside the .pub → a real round-trip.
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")
	if r := checkSignRoundtrip(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("sign-roundtrip = %s %q, want PASS", r.Severity, r.Message)
	}

	// Remove the private half → the round-trip cannot run and must SKIP (not FAIL):
	// an agent-held or hardware-token key is a normal, non-erroneous state.
	env := envFor(t, repo, Maintainer)
	if err := os.Remove(env.Git.SigningKey[:len(env.Git.SigningKey)-len(".pub")]); err != nil {
		t.Fatal(err)
	}
	if r := checkSignRoundtrip(env); r.Severity != SKIP {
		t.Errorf("sign-roundtrip (no private half) = %s %q, want SKIP", r.Severity, r.Message)
	}
}

func TestMetaTouch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// No --staged → SKIP.
	if r := checkMetaTouch(envFor(t, repo, Maintainer)); r.Severity != SKIP {
		t.Errorf("meta-touch (no --staged) = %s, want SKIP", r.Severity)
	}

	// Staged meta-path change → WARN for a maintainer, FAIL for an agent.
	stage(t, repo, ".semver-trust/note.txt", "x")
	mEnv := envFor(t, repo, Maintainer)
	mEnv.Staged = true
	if r := checkMetaTouch(mEnv); r.Severity != WARN {
		t.Errorf("meta-touch (staged meta, maintainer) = %s %q, want WARN", r.Severity, r.Message)
	}
	aEnv := envFor(t, repo, Agent)
	aEnv.Staged = true
	r := checkMetaTouch(aEnv)
	if r.Severity != FAIL {
		t.Errorf("meta-touch (staged meta, agent) = %s %q, want FAIL", r.Severity, r.Message)
	}
	if r.Preempts == "" {
		t.Errorf("meta-touch FAIL should name the meta-path gate; Preempts empty")
	}
}

func TestStagedPurity(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// Pure meta staged → PASS.
	stage(t, repo, ".semver-trust/note.txt", "x")
	pureEnv := envFor(t, repo, Maintainer)
	pureEnv.Staged = true
	if r := checkStagedPurity(pureEnv); r.Severity != PASS {
		t.Errorf("staged-purity (pure meta) = %s %q, want PASS", r.Severity, r.Message)
	}

	// Add an ordinary staged path → mixed → WARN.
	stage(t, repo, "README.md", "hi")
	mixEnv := envFor(t, repo, Maintainer)
	mixEnv.Staged = true
	if r := checkStagedPurity(mixEnv); r.Severity != WARN {
		t.Errorf("staged-purity (mixed) = %s %q, want WARN", r.Severity, r.Message)
	}
}

func TestAgentProvenance(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// The adopt commit carries no Provenance trailer → no agent-authored meta → PASS.
	if r := checkAgentProvenance(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("agent-provenance (none) = %s %q, want PASS", r.Severity, r.Message)
	}

	// Add a meta-path commit stamped Provenance: agent → WARN.
	run := func(args ...string) {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, ".semver-trust", "note.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".semver-trust/note.txt")
	run("-c", "commit.gpgsign=false", "commit", "-q", "-m", "tweak\n\nProvenance: agent")
	if r := checkAgentProvenance(envFor(t, repo, Maintainer)); r.Severity != WARN {
		t.Errorf("agent-provenance (agent meta commit) = %s %q, want WARN", r.Severity, r.Message)
	}
}

func TestPreAdoption(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}

	// An adopted repo (a policy is present) → SKIP.
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")
	if r := checkPreAdoption(envFor(t, repo, Maintainer)); r.Severity != SKIP {
		t.Errorf("pre-adoption (adopted) = %s, want SKIP", r.Severity)
	}

	// A repo with commits but no policy at HEAD → the triage WARN.
	bare := t.TempDir()
	run := func(args ...string) {
		if out, err := exec.Command("git", append([]string{"-C", bare}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "a@example.com")
	run("config", "user.name", "A")
	if err := os.WriteFile(filepath.Join(bare, "README.md"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("-c", "commit.gpgsign=false", "commit", "-q", "-m", "init")
	git, err := LoadGitConfig(bare)
	if err != nil {
		t.Fatal(err)
	}
	env := &Env{Repo: bare, Persona: Maintainer, At: time.Now(), Git: git}
	if r := checkPreAdoption(env); r.Severity != WARN {
		t.Errorf("pre-adoption (no policy) = %s %q, want WARN", r.Severity, r.Message)
	}
}

// loadDescriptor writes an inception bootstrap descriptor out-of-band (never
// inside repo, per ADR-028) and loads it, so Env.Descriptor carries the raw bytes
// Digest() needs. policyDigest and trustMaterial are the binding fields
// AuthenticateBootstrapTree checks against HEAD's tree.
func loadDescriptor(t *testing.T, repo, policyDigest string, trustMaterial map[string]string) *chain.BootstrapDescriptor {
	t.Helper()
	tm, err := json.Marshal(trustMaterial)
	if err != nil {
		t.Fatal(err)
	}
	body := `{
		"repository": "repo:test/doctor",
		"component": "app",
		"interval_mode": "inception",
		"tag_prefix": "",
		"policy_path": ".semver-trust/policy.toml",
		"policy_digest": "` + policyDigest + `",
		"verification_profile": "vp",
		"clock_profile": "cp",
		"version_predecessor": null,
		"trust_material": ` + string(tm) + `,
		"trust_roles": {"human_signers": "m/humans"},
		"mandatory_meta_paths": [".github/workflows/**"]
	}`
	oob := filepath.Join(t.TempDir(), "bootstrap.json") // out-of-band, not under repo
	if err := os.WriteFile(oob, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := chain.LoadBootstrapDescriptor(oob, repo)
	if err != nil {
		t.Fatalf("load descriptor: %v", err)
	}
	return d
}

func TestChainHead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**", ".github/workflows/**"`, "distinct")

	// No --bootstrap-descriptor → the accepted chain head is not projectable → SKIP.
	if r := checkChainHead(envFor(t, repo, Maintainer)); r.Severity != SKIP {
		t.Errorf("chain-head (no descriptor) = %s %q, want SKIP", r.Severity, r.Message)
	}

	// A descriptor with the right subject but a stale/tampered policy_digest must
	// NOT authenticate against HEAD's tree — it fails closed (FAIL), never PASS.
	env := envFor(t, repo, Maintainer)
	bogus := "sha256:" + strings.Repeat("00", 32)
	env.Descriptor = loadDescriptor(t, repo, bogus, map[string]string{"m/humans": bogus})
	r := checkChainHead(env)
	if r.Severity != FAIL {
		t.Errorf("chain-head (unbinding descriptor) = %s %q, want FAIL (fail closed)", r.Severity, r.Message)
	}
	if !strings.Contains(r.Preempts, "ADR-028") {
		t.Errorf("chain-head binding FAIL should name the §5.4/ADR-028 binding; Preempts=%q", r.Preempts)
	}

	// A descriptor whose policy_digest + trust_material actually bind HEAD's tree
	// authenticates; with no published release/v0.2 chain the bound head is genesis
	// → SKIP. This exercises the full authenticate → verifier → AcceptedChainHead-
	// BoundTo(Digest()) sequence on a genuine descriptor.
	env2 := envFor(t, repo, Maintainer)
	meta, err := verify.MetaPolicyFromTree(env2.Policy, env2.PolicyPath, repo, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	env2.Descriptor = loadDescriptor(t, repo, meta.Digest, meta.TrustMaterial)
	if r := checkChainHead(env2); r.Severity != SKIP {
		t.Errorf("chain-head (binding descriptor, no chain) = %s %q, want SKIP (genesis)", r.Severity, r.Message)
	}
}

func TestFetchRefspec(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// No attestation refspec configured → WARN with the git config --add fix.
	env := envFor(t, repo, Maintainer)
	if r := checkFetchRefspec(env); r.Severity != WARN {
		t.Errorf("fetch-refspec (unconfigured) = %s %q, want WARN", r.Severity, r.Message)
	}

	// A refspec that merely mentions the namespace but maps into refs/heads/… does
	// NOT deliver evidence where GitRefStore reads it — a substring match would
	// wrongly PASS; the exact-mapping check must still WARN.
	wrongDst := envFor(t, repo, Maintainer)
	wrongDst.Git.FetchRefspecs = []string{"+refs/attestations/*:refs/heads/attestations/*"}
	if r := checkFetchRefspec(wrongDst); r.Severity != WARN {
		t.Errorf("fetch-refspec (wrong destination namespace) = %s %q, want WARN", r.Severity, r.Message)
	}
	// The inverse mapping fetches no attestation refs at all → WARN.
	wrongSrc := envFor(t, repo, Maintainer)
	wrongSrc.Git.FetchRefspecs = []string{"+refs/heads/*:refs/attestations/*"}
	if r := checkFetchRefspec(wrongSrc); r.Severity != WARN {
		t.Errorf("fetch-refspec (wrong source) = %s %q, want WARN", r.Severity, r.Message)
	}

	// Configure the exact mapping and reload git config → PASS (also exercises the
	// --get-all reader and the optional leading +).
	if out, err := exec.Command("git", "-C", repo, "config", "--add",
		"remote.origin.fetch", "+refs/attestations/*:refs/attestations/*").CombinedOutput(); err != nil {
		t.Fatalf("git config: %v\n%s", err, out)
	}
	if r := checkFetchRefspec(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("fetch-refspec (configured) = %s %q, want PASS", r.Severity, r.Message)
	}
}

func TestEnrollmentLineCheck(t *testing.T) {
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

	// A well-formed line resolves in its declared namespace → PASS.
	env := &Env{At: time.Now(), EnrollmentLine: []byte(line + "\n")}
	if r := checkEnrollmentLine(env); r.Severity != PASS {
		t.Errorf("enrollment-line (valid) = %s %q, want PASS", r.Severity, r.Message)
	}
	// A malformed line (the problem #2 shape) → FAIL.
	env.EnrollmentLine = []byte("this is not a valid signer line\n")
	if r := checkEnrollmentLine(env); r.Severity != FAIL {
		t.Errorf("enrollment-line (malformed) = %s, want FAIL", r.Severity)
	}
	// A parse-valid line that OMITS namespaces= is unrestricted (trusted in every
	// namespace) → FAIL, not a silent PASS.
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	env.EnrollmentLine = []byte("alex@example.com " + key + "\n")
	if r := checkEnrollmentLine(env); r.Severity != FAIL {
		t.Errorf("enrollment-line (no namespace) = %s %q, want FAIL", r.Severity, r.Message)
	}
	// An explicitly EMPTY namespace (namespaces="") matches like an omitted list but
	// authorizes no production operation → FAIL.
	env.EnrollmentLine = []byte(`alex@example.com namespaces="" ` + key + "\n")
	if r := checkEnrollmentLine(env); r.Severity != FAIL {
		t.Errorf(`enrollment-line (namespaces="") = %s %q, want FAIL`, r.Severity, r.Message)
	}
	// A trailing-comma empty member (namespaces="git,") is rejected too.
	env.EnrollmentLine = []byte(`alex@example.com namespaces="git," ` + key + "\n")
	if r := checkEnrollmentLine(env); r.Severity != FAIL {
		t.Errorf(`enrollment-line (namespaces="git,") = %s %q, want FAIL`, r.Severity, r.Message)
	}
	// No candidate → SKIP.
	env.EnrollmentLine = nil
	if r := checkEnrollmentLine(env); r.Severity != SKIP {
		t.Errorf("enrollment-line (none) = %s, want SKIP", r.Severity)
	}
}

func TestRulesets(t *testing.T) {
	if r := checkRulesets(&Env{}); r.Severity != SKIP {
		t.Errorf("rulesets = %s, want SKIP (always)", r.Severity)
	}
}

func TestReleaseBaseline(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	repo, _ := doctorRepo(t, `".semver-trust/**"`, "distinct")

	// No tags → SKIP.
	if r := checkReleaseBaseline(envFor(t, repo, Maintainer)); r.Severity != SKIP {
		t.Errorf("release-baseline (no tags) = %s, want SKIP", r.Severity)
	}

	// A tag → the informational reproduction line.
	if out, err := exec.Command("git", "-C", repo, "tag", "v0.1.0").CombinedOutput(); err != nil {
		t.Fatalf("git tag: %v\n%s", err, out)
	}
	if r := checkReleaseBaseline(envFor(t, repo, Maintainer)); r.Severity != PASS {
		t.Errorf("release-baseline (tagged) = %s %q, want PASS", r.Severity, r.Message)
	}
}
