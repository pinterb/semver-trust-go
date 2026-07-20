// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/chain"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

func releaseEpochTime(t *testing.T) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, releaseEpoch)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// bobV02Verifier builds the attestation verifier SupersedeHead needs: bob enrolled
// for the attestation namespace + the release-v0.2 schema.
func bobV02Verifier(t *testing.T) *attest.Verifier {
	t.Helper()
	pub, err := os.ReadFile(bobKeyPath(t) + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	signers, err := sshsig.ParseAllowedSigners([]byte(
		"bob@semver-trust.test namespaces=\"" + attest.Namespace + "\" " + strings.TrimSpace(string(pub)) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := conformance.Vector("schemas/release-v0.2.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := attest.NewVerifier(signers, map[string][]byte{attest.PredicateReleaseV02: schema})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// setupSupersedeChain builds a repo whose genesis release/v0.2 is an UNPROMOTED
// prerelease (v0.1.0-t0.1, floored to T0 by an unreviewed agent commit) at HEAD —
// the release a promotion supersedes. Returns the repo, descriptor path, and the
// genesis (prerelease) commit.
func setupSupersedeChain(t *testing.T) (repo, descPath, genesisCommit string) {
	t.Helper()
	keys := stageVendoredKeys(t)
	repo = t.TempDir()
	if out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	commitFilesSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test", map[string]string{
		".semver-trust/policy.toml":         recurringPolicy,
		".semver-trust/allowed_signers":     treeAllowedSigners(t),
		".semver-trust/attestation_signers": treeAttestationSigners(t),
	}, "feat: adopt semver-trust\n\nProvenance: human")
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget\n", "feat: widget core\n\n"+agentTrailer)

	descPath = writeDescriptorFile(t, recurringDescriptor(t, repo))
	genesisCommit = gitOut(t, repo, "rev-parse", "HEAD")

	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--predicate", "v0.2",
		"--repository-digest", "sha256:"+repoDigestHex,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t), "--attest-key", bobKeyPath(t),
		"--tagger-name", "alice", "--tagger-email", "alice@semver-trust.test",
		"--json")
	if err != nil {
		t.Fatalf("genesis prerelease: %v\n%s", err, out)
	}
	return repo, descPath, genesisCommit
}

// TestSupersedeHeadAndVerifyMode is the C5b (verify-side) payoff: a supersede
// re-evaluates the accepted prerelease at its OWN commit. Normal v0.10 verify at
// that commit discovers the head and aborts promotion_required (the interval would
// be P..P); the Supersede mode instead re-runs the superseded's own interval so new
// evidence can be picked up. SupersedeHead resolves the superseded + its anchor.
func TestSupersedeHeadAndVerifyMode(t *testing.T) {
	repo, descPath, genesisCommit := setupSupersedeChain(t)

	// A plain v0.10 verify at the superseded commit discovers the head → recurring
	// P..P → promotion_required.
	_, rerr := runCommand(t, "verify",
		"--repo", repo, "--to", genesisCommit,
		"--bootstrap-descriptor", descPath,
		"--verify-time", releaseEpoch, "--json")
	if rerr == nil || !strings.Contains(rerr.Error(), "promotion_required") {
		t.Fatalf("plain verify at the superseded commit: error = %v, want promotion_required", rerr)
	}

	// SupersedeHead resolves the superseded (the prerelease head) and its anchor
	// (nil — the superseded is a genesis release).
	superseded, anchor, err := chain.SupersedeHead(repo, "repo:test/widget", "default", bobV02Verifier(t), releaseEpochTime(t))
	if err != nil {
		t.Fatalf("SupersedeHead: %v", err)
	}
	if superseded == nil || superseded.Tag() != "v0.1.0-t0.1" || superseded.To() != genesisCommit {
		t.Fatalf("superseded = %v, want v0.1.0-t0.1 @ %s", superseded, genesisCommit[:7])
	}
	if anchor != nil {
		t.Errorf("anchor = %+v, want nil (the superseded is a genesis release)", anchor)
	}

	// The Supersede-mode verify re-runs the superseded's own (genesis) interval at
	// the same commit WITHOUT tripping promotion_required.
	desc, err := chain.LoadBootstrapDescriptor(descPath, repo)
	if err != nil {
		t.Fatal(err)
	}
	report, err := verify.Verify(verify.Options{
		RepoPath:    repo,
		To:          genesisCommit,
		PolicyPath:  ".semver-trust/policy.toml",
		Component:   "default",
		VerifyTime:  releaseEpochTime(t),
		Bootstrap:   desc,
		Supersede:   true,
		Predecessor: anchor, // nil → the descriptor's genesis interval
	})
	if err != nil {
		t.Fatalf("Supersede-mode verify: %v", err)
	}
	// A genesis-superseded re-evaluation runs under the bootstrap authority (its own
	// original authority), not a recurring predecessor.
	if report.PolicyState == nil || report.PolicyState.Authority != "bootstrap" {
		t.Errorf("supersede policy authority = %+v, want bootstrap (genesis-superseded)", report.PolicyState)
	}
	if len(report.Commits) == 0 {
		t.Error("supersede re-evaluation classified no commits; the genesis interval should be re-run")
	}
}

// TestPromoteSupersedeToClean is the C5b-ii (release-side) payoff: `promote
// --bootstrap-descriptor` re-evaluates the accepted genesis prerelease at its OWN
// commit under the §7.5 superseded authority and, when new evidence lifts the
// decision to the clean channel, emits a release/v0.2 that supersedes the prior
// attestation and advances the chain to the clean tag on the IDENTICAL SHA — a
// real chain head the reader re-verifies end-to-end.
func TestPromoteSupersedeToClean(t *testing.T) {
	repo, descPath, genesisCommit := setupSupersedeChain(t)

	// The superseded genesis prerelease's attestation ref — what the promotion
	// supersedes (§7.3). Read it before promoting.
	store := attest.GitRefStore{Path: repo}
	priorByTag, err := store.List("v0.1.0-t0.1")
	if err != nil || len(priorByTag) != 1 {
		t.Fatalf("prior envelopes under v0.1.0-t0.1 = %d (%v), want 1", len(priorByTag), err)
	}
	wantSupersedes := attest.EnvelopeRef(genesisCommit, priorByTag[0])
	genesisDigest := storedResultingDigest(t, repo, "v0.1.0-t0.1")

	// New evidence: bob's post-hoc human review of the range lifts the unreviewed
	// agent commit from T0 to T2 (agent + distinct human = T2), clean at blast low.
	if _, rerr := runCommand(t, "attest", "review",
		"--repo", repo, "--to", "main",
		"--reviewer", "bob@semver-trust.test",
		"--pr", "https://forge.semver-trust.test/widget/pull/1",
		"--key", bobKeyPath(t),
		"--timestamp", releaseEpoch); rerr != nil {
		t.Fatalf("attest review: %v", rerr)
	}

	out, err := runCommand(t, "promote",
		"--repo", repo, "--tag", "v0.1.0-t0.1",
		"--bootstrap-descriptor", descPath,
		"--repository-digest", "sha256:"+repoDigestHex,
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t), "--attest-key", bobKeyPath(t),
		"--tagger-name", "alice", "--tagger-email", "alice@semver-trust.test",
		"--json")
	if err != nil {
		t.Fatalf("promote: %v\n%s", err, out)
	}
	var result promoteResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("promote --json does not parse: %v\n%s", err, out)
	}

	// DECISIVE: clean channel on the IDENTICAL SHA, superseding the genesis.
	if result.Channel != "clean" || result.Tag != "v0.1.0" || result.Version != "v0.1.0" {
		t.Fatalf("promotion = channel %s, tag %s, version %s; want clean v0.1.0", result.Channel, result.Tag, result.Version)
	}
	if result.PromotedFrom != "v0.1.0-t0.1" {
		t.Errorf("promoted_from = %q, want v0.1.0-t0.1", result.PromotedFrom)
	}
	if result.ToCommit != genesisCommit {
		t.Errorf("promotion to_commit = %s, want the superseded commit %s (§7.3 identical SHA)", result.ToCommit, genesisCommit)
	}
	if result.Effective != "T2" {
		t.Errorf("effective = %s, want T2 (agent + distinct human review)", result.Effective)
	}
	if result.Supersedes != wantSupersedes {
		t.Errorf("supersedes = %q, want the genesis attestation ref %q", result.Supersedes, wantSupersedes)
	}

	// The clean tag is a real signed annotated tag git verifies, on the same commit.
	cleanSHA, err := vcs.ResolveCommit(repo, "v0.1.0")
	if err != nil {
		t.Fatalf("clean tag v0.1.0 does not resolve: %v", err)
	}
	if cleanSHA != genesisCommit {
		t.Errorf("clean tag at %s, want the superseded commit %s", cleanSHA, genesisCommit)
	}
	verifyTagWithGit(t, repo, "v0.1.0")

	// The stored release/v0.2 binds the supersede: action supersede (not genesis),
	// the superseded prerelease as version predecessor, and prior_state chaining to
	// the genesis resulting_state.digest (§8.1/ADR-036 hash-chain link).
	promo := storedRecurringDoc(t, repo, "v0.1.0")
	vs := promo.Predicate.VersionState
	if vs.Genesis || vs.Action != "supersede" {
		t.Errorf("version_state = genesis=%v action=%q, want false/supersede", vs.Genesis, vs.Action)
	}
	if vs.Predecessor == nil || vs.Predecessor.Name != "v0.1.0-t0.1" {
		t.Errorf("version_state.predecessor = %+v, want v0.1.0-t0.1 (the superseded)", vs.Predecessor)
	}
	if vs.PriorState == nil || vs.PriorState.Digest["sha256"] != genesisDigest {
		t.Errorf("prior_state.digest = %+v, want the genesis resulting digest %s (chain link)", vs.PriorState, genesisDigest)
	}

	// DECISIVE: the promotion is a real accepted chain head. The reader re-verifies
	// the WHOLE chain (genesis prerelease → promotion) from scratch — reproducing
	// every resulting_state digest, the prior_state link, AND the supersede's
	// decision.supersedes (checkSupersedes) — and selects v0.1.0 as the unique head.
	head, err := chain.AcceptedChainHead(repo, "repo:test/widget", "default", bobV02Verifier(t), releaseEpochTime(t))
	if err != nil {
		t.Fatalf("AcceptedChainHead after promotion: %v", err)
	}
	if head == nil || head.Tag() != "v0.1.0" || head.To() != genesisCommit {
		t.Fatalf("accepted head after promotion = %v, want the clean v0.1.0 at %s", head, genesisCommit)
	}
}

// TestPromoteSupersedeRefusesUnchangedEvidence: promotion is not re-cutting. With
// no new review, the supersede re-evaluation still lands in the pre-release channel,
// so the v0.10 promotion refuses and writes nothing (§7.3, §7.2).
func TestPromoteSupersedeRefusesUnchangedEvidence(t *testing.T) {
	repo, descPath, _ := setupSupersedeChain(t)
	tagsBefore, err := vcs.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}
	refsBefore := attestationRefs(t, repo)

	_, err = runCommand(t, "promote",
		"--repo", repo, "--tag", "v0.1.0-t0.1",
		"--bootstrap-descriptor", descPath,
		"--repository-digest", "sha256:"+repoDigestHex,
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t), "--attest-key", bobKeyPath(t),
		"--tagger-name", "alice", "--tagger-email", "alice@semver-trust.test")
	if err == nil {
		t.Fatal("promote succeeded though the evidence had not changed the decision")
	}
	if !strings.Contains(err.Error(), "still lands in the pre-release channel") {
		t.Errorf("error = %q, want the unchanged-evidence refusal", err)
	}
	assertNoCleanTag(t, repo, tagsBefore)
	if refsAfter := attestationRefs(t, repo); len(refsAfter) != len(refsBefore) {
		t.Errorf("refused promotion stored something: before %v, after %v", refsBefore, refsAfter)
	}
}

// TestPromoteSupersedeRejectsTrustMaterialOverride: on the v0.10 supersede path the
// descriptor pins trust material by digest from TO's tree, so a filesystem override
// must be rejected FAIL-FAST — not silently ignored — matching the release/v0.10
// key-substitution guard (§5.4/ADR-028). The rejection fires before the chain
// verifier is built (AttestationVerifier) AND on the re-verification (Verify), so no
// override can slip an unpinned key into either verification. Nothing is written.
func TestPromoteSupersedeRejectsTrustMaterialOverride(t *testing.T) {
	for _, tc := range []struct{ flag, value string }{
		{"--allowed-signers", allowedSignersPath(t)},
		{"--gpg-keyring", allowedSignersPath(t)}, // any non-empty path; rejected before it is read
		{"--attestation-signers", bobAttestationSigners(t)},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			repo, descPath, _ := setupSupersedeChain(t)
			tagsBefore, err := vcs.Tags(repo)
			if err != nil {
				t.Fatal(err)
			}
			refsBefore := attestationRefs(t, repo)

			_, err = runCommand(t, "promote",
				"--repo", repo, "--tag", "v0.1.0-t0.1",
				"--bootstrap-descriptor", descPath,
				"--repository-digest", "sha256:"+repoDigestHex,
				tc.flag, tc.value,
				"--verify-time", releaseEpoch,
				"--tag-key", bobKeyPath(t), "--attest-key", bobKeyPath(t),
				"--tagger-name", "alice", "--tagger-email", "alice@semver-trust.test")
			if err == nil {
				t.Fatalf("promote honored %s on the v0.10 path — a key-substitution bypass", tc.flag)
			}
			if !strings.Contains(err.Error(), "descriptor-pinned trust material") {
				t.Errorf("error = %q, want the v0.10 trust-material-override rejection", err)
			}
			assertNoCleanTag(t, repo, tagsBefore)
			if refsAfter := attestationRefs(t, repo); len(refsAfter) != len(refsBefore) {
				t.Errorf("refused override stored something: before %v, after %v", refsBefore, refsAfter)
			}
		})
	}
}

// TestPromoteSupersedeDryRunWritesNothing: --dry-run evaluates, decides, prints the
// would-be superseding release/v0.2 (a schema-valid preview with emission.tag null),
// and writes nothing — no clean tag, no attestation ref.
func TestPromoteSupersedeDryRunWritesNothing(t *testing.T) {
	repo, descPath, genesisCommit := setupSupersedeChain(t)
	wantSupersedes := func() string {
		byTag, err := (attest.GitRefStore{Path: repo}).List("v0.1.0-t0.1")
		if err != nil || len(byTag) != 1 {
			t.Fatalf("prior envelopes = %d (%v), want 1", len(byTag), err)
		}
		return attest.EnvelopeRef(genesisCommit, byTag[0])
	}()

	if _, rerr := runCommand(t, "attest", "review",
		"--repo", repo, "--to", "main",
		"--reviewer", "bob@semver-trust.test",
		"--pr", "https://forge.semver-trust.test/widget/pull/1",
		"--key", bobKeyPath(t), "--timestamp", releaseEpoch); rerr != nil {
		t.Fatalf("attest review: %v", rerr)
	}
	tagsBefore, err := vcs.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}
	refsBefore := attestationRefs(t, repo)

	out, err := runCommand(t, "promote",
		"--repo", repo, "--tag", "v0.1.0-t0.1",
		"--bootstrap-descriptor", descPath,
		"--repository-digest", "sha256:"+repoDigestHex,
		"--verify-time", releaseEpoch,
		"--dry-run", "--json")
	if err != nil {
		t.Fatalf("promote --dry-run: %v\n%s", err, out)
	}
	var result promoteResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("dry-run output does not parse: %v\n%s", err, out)
	}
	if !result.DryRun || result.Tag != "v0.1.0" || result.Channel != "clean" {
		t.Errorf("dry-run result = %+v, want dry-run clean v0.1.0", result)
	}
	if result.Supersedes != wantSupersedes {
		t.Errorf("dry-run supersedes = %q, want the genesis attestation ref %q", result.Supersedes, wantSupersedes)
	}
	if len(result.Statement) == 0 {
		t.Fatal("dry-run did not print the would-be statement")
	}
	validateReleaseV02Payload(t, result.Statement)

	assertNoCleanTag(t, repo, tagsBefore)
	if refsAfter := attestationRefs(t, repo); len(refsAfter) != len(refsBefore) {
		t.Errorf("dry-run stored something: before %v, after %v", refsBefore, refsAfter)
	}
}
