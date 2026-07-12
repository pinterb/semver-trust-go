// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// cutUnreviewedPreRelease cuts the demoted pre-release the release fixture's
// unreviewed v0.1.0..main range produces, at iteration 2 (the fixture already
// tags v0.1.1-t0.1) — a real release attestation stored under the tag, the
// thing a promotion later supersedes. It returns the pre-release result.
func cutUnreviewedPreRelease(t *testing.T, repo string) releaseResultJSON {
	t.Helper()
	out, err := runCommand(t, "release",
		"--repo", repo,
		"--from", "v0.1.0",
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--claimed-bump", "patch",
		"--blast", "low",
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t),
		"--attest-key", bobKeyPath(t),
		"--tagger-name", "bob",
		"--tagger-email", "bob@semver-trust.test",
		"--iteration", "2",
		"--json")
	if err != nil {
		t.Fatalf("cutting the pre-release: %v", err)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("pre-release --json output does not parse: %v\n%s", err, out)
	}
	if result.Channel != "prerelease" || result.Tag != "v0.1.1-t0.2" {
		t.Fatalf("pre-release = channel %s, tag %s; want prerelease v0.1.1-t0.2", result.Channel, result.Tag)
	}
	return result
}

// The acceptance e2e (spec §7.3 / ADR-009): the unreviewed release fixture
// cuts the demoted pre-release v0.1.1-t0.2 with a stored attestation; bob's
// post-hoc reviews then land; `promote --tag v0.1.1-t0.2` re-decides at the
// IDENTICAL SHA (alice→T3, ci-bot→T2, own floor T2, effective T2, blast low is
// the §6.4 clean cell) and cuts the clean v0.1.1 on that same commit, with a
// release attestation that validates against the vendored schema and whose
// supersedes points at the prior envelope's stable ref — the promotion chain.
func TestPromoteCleanSupersedes(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")

	prior := cutUnreviewedPreRelease(t, repo)
	// The pre-release's commit-subject ref is what the promotion supersedes.
	if len(prior.StoredRefs) != 2 {
		t.Fatalf("pre-release stored refs = %v, want 2 (commit + tag)", prior.StoredRefs)
	}
	priorCommitRef := prior.StoredRefs[0]
	preReleaseSHA, err := vcs.ResolveCommit(repo, "v0.1.1-t0.2")
	if err != nil {
		t.Fatal(err)
	}

	// New evidence: bob's post-hoc review over the range.
	emitBobReviewOverRoot(t, repo)

	out, err := runCommand(t, "promote",
		"--repo", repo,
		"--tag", "v0.1.1-t0.2",
		"--allowed-signers", allowedSignersPath(t),
		"--attestation-signers", bobAttestationSigners(t),
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t),
		"--attest-key", bobKeyPath(t),
		"--tagger-name", "bob",
		"--tagger-email", "bob@semver-trust.test",
		"--json")
	if err != nil {
		t.Fatalf("promote: %v", err)
	}

	var result promoteResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("promote --json output does not parse: %v\n%s", err, out)
	}

	// DECISIVE: the promotion lands the clean channel, and the clean tag sits
	// on the IDENTICAL SHA the pre-release did — no source moved (§7.3).
	if result.Channel != "clean" || result.Tag != "v0.1.1" || result.Version != "v0.1.1" {
		t.Errorf("promotion = channel %s, tag %s, version %s; want clean v0.1.1", result.Channel, result.Tag, result.Version)
	}
	if result.PromotedFrom != "v0.1.1-t0.2" {
		t.Errorf("promoted_from = %q, want v0.1.1-t0.2", result.PromotedFrom)
	}
	if result.Effective != "T2" || result.Bump != "patch" || result.ClaimedBump != "patch" {
		t.Errorf("carried decision = effective %s, bump %s, claimed %s; want T2/patch/patch (claim carried from the prior attestation)",
			result.Effective, result.Bump, result.ClaimedBump)
	}
	cleanSHA, err := vcs.ResolveCommit(repo, "v0.1.1")
	if err != nil {
		t.Fatalf("clean tag v0.1.1 does not resolve: %v", err)
	}
	if cleanSHA != preReleaseSHA || cleanSHA != result.ToCommit {
		t.Errorf("clean tag at %s, pre-release at %s, result.to_commit %s; §7.3 requires the identical SHA",
			cleanSHA, preReleaseSHA, result.ToCommit)
	}
	// The clean tag is a real signed annotated tag git itself verifies.
	verifyTagWithGit(t, repo, "v0.1.1")

	// DECISIVE: supersedes points at the prior envelope's stable commit ref.
	if result.Supersedes != priorCommitRef {
		t.Errorf("supersedes = %q, want the prior envelope's commit ref %q", result.Supersedes, priorCommitRef)
	}

	// Both envelopes are retrievable — the prior under its pre-release tag, the
	// promotion under the clean tag — and the promotion's payload validates
	// against the vendored schema independently and carries the supersedes ref.
	store := attest.GitRefStore{Path: repo}
	priorByTag, err := store.List("v0.1.1-t0.2")
	if err != nil || len(priorByTag) != 1 {
		t.Fatalf("prior envelopes under v0.1.1-t0.2 = %d (%v), want 1", len(priorByTag), err)
	}
	newByTag, err := store.List("v0.1.1")
	if err != nil || len(newByTag) != 1 {
		t.Fatalf("promotion envelopes under v0.1.1 = %d (%v), want 1", len(newByTag), err)
	}
	// The supersedes ref actually names the prior envelope's content digest.
	if got := attest.EnvelopeRef(preReleaseSHA, priorByTag[0]); got != result.Supersedes {
		t.Errorf("supersedes %q does not name the prior envelope (EnvelopeRef = %q)", result.Supersedes, got)
	}

	payload := envelopePayload(t, newByTag[0])
	validateReleasePayload(t, payload)

	var stmt releasePayloadJSON
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatal(err)
	}
	if stmt.Subject[0].Name != "v0.1.1" || stmt.Subject[0].Digest["gitCommit"] != preReleaseSHA {
		t.Errorf("subject = %+v, want v0.1.1 bound to the same commit", stmt.Subject)
	}
	if stmt.Predicate.Decision.Channel != "clean" {
		t.Errorf("decision.channel = %q, want clean", stmt.Predicate.Decision.Channel)
	}
	if stmt.Predicate.Decision.Supersedes == nil || *stmt.Predicate.Decision.Supersedes != priorCommitRef {
		t.Errorf("payload decision.supersedes = %v, want %q", stmt.Predicate.Decision.Supersedes, priorCommitRef)
	}
	// The provenance vector lifted under the new evidence — the very reason the
	// decision moved to clean.
	if stmt.Predicate.Trust.Effective != "T2" || stmt.Predicate.Trust.Own != "T2" {
		t.Errorf("trust = %+v, want effective/own T2", stmt.Predicate.Trust)
	}
}

// Refusal: nothing to supersede. The fixture tags v0.1.1-t0.1 but never stores
// a release attestation under it; promoting it fails outright and writes
// nothing.
func TestPromoteRefusesNoPriorAttestation(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	tagsBefore, err := vcs.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}

	_, err = runCommand(t, "promote",
		"--repo", repo,
		"--tag", "v0.1.1-t0.1",
		"--allowed-signers", allowedSignersPath(t),
		"--attestation-signers", bobAttestationSigners(t),
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t),
		"--attest-key", bobKeyPath(t),
		"--tagger-name", "bob",
		"--tagger-email", "bob@semver-trust.test")
	if err == nil {
		t.Fatal("promote succeeded with no prior release attestation to supersede")
	}
	if !strings.Contains(err.Error(), "nothing to supersede") {
		t.Errorf("error = %q, want it to mention nothing to supersede", err)
	}
	assertNoCleanTag(t, repo, tagsBefore)
	if refs := attestationRefs(t, repo); len(refs) != 0 {
		t.Errorf("attestation store not empty on refusal: %v", refs)
	}
}

// Refusal: unchanged evidence. The pre-release is cut, then promoted WITHOUT
// any new review — the re-decision still lands in the pre-release channel, and
// promotion is not re-cutting, so it refuses. No clean tag appears.
func TestPromoteRefusesUnchangedEvidence(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	cutUnreviewedPreRelease(t, repo)
	tagsBefore, err := vcs.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}

	_, err = runCommand(t, "promote",
		"--repo", repo,
		"--tag", "v0.1.1-t0.2",
		"--allowed-signers", allowedSignersPath(t),
		// No --attestation-signers and no new review: the evidence is exactly
		// what produced the pre-release.
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t),
		"--attest-key", bobKeyPath(t),
		"--tagger-name", "bob",
		"--tagger-email", "bob@semver-trust.test")
	if err == nil {
		t.Fatal("promote succeeded though the evidence had not changed the decision")
	}
	if !strings.Contains(err.Error(), "evidence has not changed the decision") {
		t.Errorf("error = %q, want the unchanged-evidence refusal", err)
	}
	assertNoCleanTag(t, repo, tagsBefore)
}

// Refusal: the clean tag already exists. Promotion never overwrites a
// published clean release (§7.3); with v0.1.1 already tagged, a qualifying
// promotion refuses before signing anything.
func TestPromoteRefusesExistingCleanTag(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	cutUnreviewedPreRelease(t, repo)
	emitBobReviewOverRoot(t, repo)
	gitCLI(t, repo, "tag", "v0.1.1") // the clean tag is already taken

	_, err := runCommand(t, "promote",
		"--repo", repo,
		"--tag", "v0.1.1-t0.2",
		"--allowed-signers", allowedSignersPath(t),
		"--attestation-signers", bobAttestationSigners(t),
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t),
		"--attest-key", bobKeyPath(t),
		"--tagger-name", "bob",
		"--tagger-email", "bob@semver-trust.test")
	if err == nil {
		t.Fatal("promote created a clean tag that already existed")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, want the existing-tag refusal", err)
	}
	// Only the prior release attestation is stored under the pre-release tag —
	// no superseding envelope was written under v0.1.1.
	if byTag, err := (attest.GitRefStore{Path: repo}).List("v0.1.1"); err != nil || len(byTag) != 0 {
		t.Errorf("envelopes under v0.1.1 = %d (%v), want 0 (nothing written on refusal)", len(byTag), err)
	}
}

// --dry-run evaluates, decides, prints the would-be superseding attestation,
// and writes nothing: no clean tag, no new attestation ref.
func TestPromoteDryRunWritesNothing(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")
	prior := cutUnreviewedPreRelease(t, repo)
	emitBobReviewOverRoot(t, repo)
	tagsBefore, err := vcs.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}
	refsBefore := attestationRefs(t, repo)

	out, err := runCommand(t, "promote",
		"--repo", repo,
		"--tag", "v0.1.1-t0.2",
		"--allowed-signers", allowedSignersPath(t),
		"--attestation-signers", bobAttestationSigners(t),
		"--verify-time", releaseEpoch,
		"--dry-run",
		"--json")
	if err != nil {
		t.Fatalf("promote --dry-run: %v", err)
	}
	var result promoteResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output does not parse: %v", err)
	}
	if !result.DryRun || result.Tag != "v0.1.1" || result.Channel != "clean" {
		t.Errorf("dry-run result = %+v", result)
	}
	if result.Supersedes != prior.StoredRefs[0] {
		t.Errorf("dry-run supersedes = %q, want the prior commit ref %q", result.Supersedes, prior.StoredRefs[0])
	}
	if len(result.Statement) == 0 {
		t.Error("dry-run did not print the would-be statement")
	}
	validateReleasePayload(t, result.Statement)

	assertNoCleanTag(t, repo, tagsBefore)
	if refsAfter := attestationRefs(t, repo); len(refsAfter) != len(refsBefore) {
		t.Errorf("dry-run stored something: before %v, after %v", refsBefore, refsAfter)
	}
}

// assertNoCleanTag asserts the clean tag v0.1.1 was not created — the tag set
// is unchanged from before the refused/dry-run promotion.
func assertNoCleanTag(t *testing.T, repo string, before []string) {
	t.Helper()
	after, err := vcs.Tags(repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("tag set changed: before %v, after %v", before, after)
	}
	if exists, err := vcs.TagExists(repo, "v0.1.1"); err != nil {
		t.Fatal(err)
	} else if exists {
		t.Error("clean tag v0.1.1 was created")
	}
}

// promoteResultJSON mirrors the promote --json output shape.
type promoteResultJSON struct {
	DryRun        bool            `json:"dry_run"`
	Tag           string          `json:"tag"`
	PromotedFrom  string          `json:"promoted_from"`
	Channel       string          `json:"channel"`
	Version       string          `json:"version"`
	ToCommit      string          `json:"to_commit"`
	Bump          string          `json:"bump"`
	ClaimedBump   string          `json:"claimed_bump"`
	SemanticFloor string          `json:"semantic_floor"`
	Effective     string          `json:"effective"`
	Own           string          `json:"own"`
	Blast         string          `json:"blast"`
	Supersedes    string          `json:"supersedes"`
	StoredRefs    []string        `json:"stored_refs"`
	Statement     json.RawMessage `json:"statement"`
}
