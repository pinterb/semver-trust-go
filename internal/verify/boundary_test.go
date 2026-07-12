// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// The ADR-026 adoption-boundary tests build their repository in-test (plain
// git via os/exec, the build-fixture-repos.sh pattern; determinism is not
// required for an in-test repo). The history mirrors the live case that
// motivated the ADR — the earliest commit's public key is lost:
//
//	commit1 (tag v0-import)  signed by unknown-mallory — UNENROLLED: the
//	                         pre-scheme commit no registry can verify.
//	commit2                  alice adopts the scheme: policy WITHOUT a
//	                         boundary lands in the tree.
//	commit3 (main)           alice declares adoption_boundary = "v0-import".
//
// Verifying root..commit2 aborts on commit1 (unverifiable is never T0);
// verifying commit3 with no FROM anchors at boundary..TO and proceeds, with
// the boundary disclosed and commit1 contributing nothing.

const boundaryPolicyHeader = `# semver-trust TEST POLICY - in-test adoption-boundary repo (ADR-026)
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"
`

const boundaryPolicyTail = `
[meta]
paths          = [".semver-trust/**"]
required_level = "T2"
`

// stageKeys copies the vendored test keys into a private 0600 staging dir:
// ssh-keygen -Y sign refuses group/other-readable private keys, and the
// vendored copies land with ordinary modes (build-fixture-repos.sh pattern).
func stageKeys(t *testing.T) string {
	t.Helper()
	src := filepath.Join(cryptoVendorDir(t), "keys")
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("reading vendored keys: %v", err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatalf("reading key %s: %v", e.Name(), err)
		}
		mode := os.FileMode(0o600)
		if strings.HasSuffix(e.Name(), ".pub") {
			mode = 0o644
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, mode); err != nil {
			t.Fatalf("staging key %s: %v", e.Name(), err)
		}
	}
	return dst
}

func gitRun(t *testing.T, repo string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commitSigned writes file, stages it, and commits it SSH-signed by the
// staged key, returning the commit SHA. Configuration is pinned
// per-invocation so the developer's git config never leaks in.
func commitSigned(t *testing.T, repo, keys, key, identity, file, content, message string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, file)), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", file, err)
	}
	if err := os.WriteFile(filepath.Join(repo, file), []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", file, err)
	}
	gitRun(t, repo, "add", file)
	gitRun(t, repo,
		"-c", "user.name="+strings.SplitN(identity, "@", 2)[0],
		"-c", "user.email="+identity,
		"-c", "gpg.format=ssh",
		"-c", "user.signingkey="+filepath.Join(keys, key),
		"-c", "commit.gpgsign=true",
		"commit", "--quiet", "-m", message)
	return gitRun(t, repo, "rev-parse", "HEAD")
}

// buildBoundaryRepo constructs the three-commit history above and returns the
// repo path plus the pre-boundary and adoption-commit SHAs.
func buildBoundaryRepo(t *testing.T) (repo, preBoundarySHA, adoptionSHA string) {
	t.Helper()
	keys := stageKeys(t)
	repo = t.TempDir()
	out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1", repo).CombinedOutput()
	if err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	preBoundarySHA = commitSigned(t, repo, keys, "unknown-mallory", "mallory@semver-trust.test",
		"pre.txt", "pre-scheme content\n", "feat: pre-scheme change\n\nProvenance: human")
	gitRun(t, repo, "tag", "v0-import")

	adoptionSHA = commitSigned(t, repo, keys, "human-alice", "alice@semver-trust.test",
		".semver-trust/policy.toml", boundaryPolicyHeader+boundaryPolicyTail,
		"feat: adopt semver-trust\n\nProvenance: human")

	withBoundary := boundaryPolicyHeader + "adoption_boundary = \"v0-import\"\n" + boundaryPolicyTail
	commitSigned(t, repo, keys, "human-alice", "alice@semver-trust.test",
		".semver-trust/policy.toml", withBoundary,
		"fix: declare adoption boundary (ADR-026)\n\nProvenance: human")
	return repo, preBoundarySHA, adoptionSHA
}

// TestVerifyAdoptionBoundary is the before/after acceptance for ADR-026:
// without a declared boundary a first release aborts on the unverifiable
// pre-scheme commit; with the boundary declared in the TO tree's policy the
// same repository verifies boundary..TO, disclosing the boundary and giving
// the pre-boundary commit no level and no scope at all.
func TestVerifyAdoptionBoundary(t *testing.T) {
	repo, preSHA, adoptionSHA := buildBoundaryRepo(t)

	// Before: the policy at commit2's tree declares no boundary, so a first
	// release is root..TO and commit1's unenrolled signer aborts step 3.
	_, err := Verify(Options{
		RepoPath:           repo,
		From:               "",
		To:                 adoptionSHA,
		PolicyPath:         ".semver-trust/policy.toml",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	})
	assertAbortStep(t, err, stepSignature)
	if !errors.Is(err, vcs.ErrUnknownSigner) {
		t.Errorf("pre-boundary abort = %v, want %v", err, vcs.ErrUnknownSigner)
	}

	// After: TO's tree declares adoption_boundary = "v0-import"; the first
	// release anchors at boundary..TO and proceeds past step 3.
	report, err := Verify(Options{
		RepoPath:           repo,
		From:               "",
		To:                 "main",
		PolicyPath:         ".semver-trust/policy.toml",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("Verify with declared boundary: %v", err)
	}

	// Disclosure (ADR-026): the boundary is marked and resolved in the report.
	if !report.FromIsAdoptionBoundary {
		t.Error("FromIsAdoptionBoundary = false, want true")
	}
	if report.From != "v0-import" {
		t.Errorf("From = %q, want the declared boundary %q", report.From, "v0-import")
	}
	if report.AdoptionBoundary != preSHA {
		t.Errorf("AdoptionBoundary = %q, want resolved SHA %q", report.AdoptionBoundary, preSHA)
	}

	// The pre-boundary commit contributes NOTHING: it is absent from the
	// commit list (no level) and none of its paths reach any scope.
	if len(report.Commits) != 2 {
		t.Fatalf("commits = %d, want 2 (post-boundary only)", len(report.Commits))
	}
	for _, c := range report.Commits {
		if c.SHA == preSHA {
			t.Errorf("pre-boundary commit %s present in the commit list", preSHA)
		}
		for _, p := range c.Paths {
			if p == "pre.txt" {
				t.Errorf("pre-boundary path %q leaked into commit %s", p, c.Short)
			}
		}
	}
	for _, s := range report.Scopes {
		for _, sha := range s.Commits {
			if strings.HasPrefix(preSHA, sha) || sha == preSHA {
				t.Errorf("pre-boundary commit %s leaked into scope %s", sha, s.Scope)
			}
		}
	}

	// The human rendering discloses the boundary prominently in step 2.
	var text strings.Builder
	if err := report.WriteText(&text); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	want := "range: v0-import..main (FROM is the adoption boundary declared in policy — history before it is exempt and makes no claim; ADR-026)"
	if !strings.Contains(text.String(), want) {
		t.Errorf("human output missing boundary disclosure %q:\n%s", want, text.String())
	}

	// An explicit FROM makes the boundary irrelevant: no boundary marking.
	explicit, err := Verify(Options{
		RepoPath:           repo,
		From:               "v0-import",
		To:                 "main",
		PolicyPath:         ".semver-trust/policy.toml",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("Verify with explicit FROM: %v", err)
	}
	if explicit.FromIsAdoptionBoundary || explicit.AdoptionBoundary != "" {
		t.Errorf("explicit FROM marked as boundary: %+v", explicit)
	}
}

// A boundary that does not resolve aborts step 2 with an error naming the
// policy as the boundary's source (the operator must know where it came from).
func TestVerifyAdoptionBoundaryUnresolvable(t *testing.T) {
	repo, _, _ := buildBoundaryRepo(t)
	pol := minimalPolicy(t)
	pol.AdoptionBoundary = "no-such-rev"

	_, err := verifyWith(Options{
		RepoPath:           repo,
		To:                 "main",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	}, pol)
	assertAbortStep(t, err, stepEnumerate)
	for _, want := range []string{"no-such-rev", "adoption_boundary", "ADR-026", "does not resolve"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

// A boundary that is not an ancestor of TO fails vcs.Range's §10.2 check;
// the abort names the boundary's policy provenance.
func TestVerifyAdoptionBoundaryNotAncestor(t *testing.T) {
	repo, _, _ := buildBoundaryRepo(t)
	keys := stageKeys(t)
	gitRun(t, repo, "checkout", "--quiet", "-b", "side", "v0-import")
	commitSigned(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"side.txt", "side content\n", "feat: side change\n\nProvenance: human")
	gitRun(t, repo, "tag", "side-tip")
	gitRun(t, repo, "checkout", "--quiet", "main")

	pol := minimalPolicy(t)
	pol.AdoptionBoundary = "side-tip"

	_, err := verifyWith(Options{
		RepoPath:           repo,
		To:                 "main",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	}, pol)
	assertAbortStep(t, err, stepEnumerate)
	for _, want := range []string{"§10.2", "not an ancestor", "adoption_boundary", "ADR-026"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}
