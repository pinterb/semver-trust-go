// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// Appendix A step 3, mechanically: a maintainer (bob) reviews the commits
// after the fact, a signed review attestation lands in the repository, and
// verification lifts the levels per §3.2.
//
// Before the attestation, the release fixture verifies v0.1.0..main with
// alice at T2 (human/none), ci-bot at T0 (agent/none), own floor T0 — and
// the root..main range ABORTS outright at §5.4, because the setup commit
// touches .semver-trust/** at T2 while the policy requires T3 on meta-paths.
//
// After bob's review attestation covers every commit of root..main:
//   - alice's commits classify human/human_distinct → T3 (author alice +
//     distinct human reviewer bob: two accountable humans),
//   - ci-bot's commit classifies agent/human_distinct → T2 (one accountable
//     human, in the reviewer role),
//   - the own floor lifts T0 → T2, meeting the policy threshold, and
//   - root..main now PASSES §5.4 (the setup commit reached the required T3),
//     so §10 steps 1–7 succeed on a history that failed before.
func TestReviewAttestationLiftsLevels(t *testing.T) {
	fixtures := buildFixtures(t)
	repo := filepath.Join(fixtures, "release")

	// ---- Before: v0.1.0..main floors to T0; root..main aborts at §5.4. -----
	before, err := Verify(Options{
		RepoPath:           repo,
		From:               "v0.1.0",
		To:                 "main",
		PolicyPath:         ".semver-trust/policy.toml",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("before-verify: %v", err)
	}
	beforeBySigner := commitsBySigner(before.Commits)
	assertCommit(t, beforeBySigner["alice@semver-trust.test"], "T2", "human", "none")
	assertCommit(t, beforeBySigner["ci-bot@semver-trust.test"], "T0", "agent", "none")
	if before.Scopes[0].OwnFloor != "T0" {
		t.Fatalf("before own floor = %s, want T0", before.Scopes[0].OwnFloor)
	}
	_, err = Verify(Options{
		RepoPath:           repo,
		From:               "", // root..main includes the meta-path setup commit
		To:                 "main",
		PolicyPath:         ".semver-trust/policy.toml",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	})
	assertAbortStep(t, err, stepMetaPath)

	// ---- Emit: bob reviews every commit of root..main, post hoc (§7.3). ----
	// The vendored test-only key stays inside the test tree (AGENTS.md gate
	// 2); signing happens in Go, so no 0600 staging copy is needed — that
	// dance is ssh-keygen's, not ssh.ParsePrivateKey's.
	subjects := rangeSHAs(t, repo, "", "main")
	if len(subjects) != 3 {
		t.Fatalf("root..main = %d commits, want 3", len(subjects))
	}
	emission := emitBobReview(t, subjects)
	if _, err := attest.StoreForSubjects(attest.GitRefStore{Path: repo}, subjects, emission.Envelope); err != nil {
		t.Fatalf("storing envelopes: %v", err)
	}

	// Without an attestation-signer registry the stored review is honest
	// degradation, not a lift: levels stay put and the note says why (§4.3).
	unverified, err := Verify(Options{
		RepoPath:           repo,
		From:               "v0.1.0",
		To:                 "main",
		PolicyPath:         ".semver-trust/policy.toml",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("no-registry verify: %v", err)
	}
	for _, c := range unverified.Commits {
		if c.Level != beforeBySigner[c.Signer].Level {
			t.Errorf("no-registry: commit %s lifted to %s without a verifiable attestation", c.Short, c.Level)
		}
		if !strings.Contains(c.ReviewNote, "unverifiable") {
			t.Errorf("no-registry: commit %s note = %q, want the degradation named", c.Short, c.ReviewNote)
		}
	}

	// ---- After: verify with bob enrolled for the attestation namespace. ----
	attSigners := bobAttestationRegistry(t)
	after, err := Verify(Options{
		RepoPath:               repo,
		From:                   "v0.1.0",
		To:                     "main",
		PolicyPath:             ".semver-trust/policy.toml",
		AllowedSignersPath:     allowedSignersPath(t),
		AttestationSignersPath: attSigners,
		VerifyTime:             pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("after-verify: %v", err)
	}
	afterBySigner := commitsBySigner(after.Commits)
	// alice authored, bob reviewed: two distinct accountable humans → T3.
	assertCommit(t, afterBySigner["alice@semver-trust.test"], "T3", "human", "human_distinct")
	// ci-bot authored, bob reviewed: one accountable human (reviewer) → T2.
	assertCommit(t, afterBySigner["ci-bot@semver-trust.test"], "T2", "agent", "human_distinct")
	if got := after.Scopes[0].OwnFloor; got != "T2" {
		t.Errorf("after own floor = %s, want T2 (lifted from T0)", got)
	}

	// The previously-aborting root..main range now runs §10 steps 1-7 to
	// completion: the setup commit reached the required T3, so §5.4 passes.
	full, err := Verify(Options{
		RepoPath:               repo,
		From:                   "",
		To:                     "main",
		PolicyPath:             ".semver-trust/policy.toml",
		AllowedSignersPath:     allowedSignersPath(t),
		AttestationSignersPath: attSigners,
		VerifyTime:             pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("root..main after the review attestation: %v", err)
	}
	if !full.MetaPath.Passed || len(full.MetaPath.Violations) != 0 {
		t.Errorf("meta-path = %+v, want passed", full.MetaPath)
	}
	if len(full.Commits) != 3 {
		t.Fatalf("root..main commits = %d, want 3", len(full.Commits))
	}
	for _, c := range full.Commits {
		want := "T3"
		if c.Signer == "ci-bot@semver-trust.test" {
			want = "T2"
		}
		if c.Level != want {
			t.Errorf("root..main commit %s (%s) = %s, want %s", c.Short, c.Signer, c.Level, want)
		}
	}
	if got := full.Scopes[0].OwnFloor; got != "T2" {
		t.Errorf("root..main own floor = %s, want T2", got)
	}
}

// A review attestation signed by a key that is NOT enrolled in the given
// attestation registry aborts the run (§8.2: a stored attestation that fails
// verification is a fail-closed stop, never a skip).
func TestStoredReviewByUnenrolledSignerAborts(t *testing.T) {
	fixtures := buildFixtures(t)
	repo := filepath.Join(fixtures, "release")

	subjects := rangeSHAs(t, repo, "v0.1.0", "main")
	emission := emitBobReview(t, subjects)
	if _, err := attest.StoreForSubjects(attest.GitRefStore{Path: repo}, subjects, emission.Envelope); err != nil {
		t.Fatal(err)
	}

	// The vendored attestation registry enrolls only ci-bot — bob's
	// signature must abort as an unknown signer.
	vendoredRegistry := filepath.Join(cryptoVendorDir(t), "attestations", "allowed_signers")
	_, err := Verify(Options{
		RepoPath:               repo,
		From:                   "v0.1.0",
		To:                     "main",
		PolicyPath:             ".semver-trust/policy.toml",
		AllowedSignersPath:     allowedSignersPath(t),
		AttestationSignersPath: vendoredRegistry,
		VerifyTime:             pinnedEpoch,
	})
	assertAbortStep(t, err, stepAttestation)
}

// emitBobReview emits bob's §4.3 review attestation over the subject SHAs,
// signed with the vendored test-only human-bob key at the pinned epoch.
func emitBobReview(t *testing.T, subjects []string) attest.Emission {
	t.Helper()
	keyBytes, err := os.ReadFile(filepath.Join(cryptoVendorDir(t), "keys", "human-bob"))
	if err != nil {
		t.Fatalf("reading vendored test key: %v", err)
	}
	signer, err := sshsig.LoadSigner(keyBytes)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	schema, err := conformance.Vector("schemas/review-v0.1.json")
	if err != nil {
		t.Fatal(err)
	}
	emitter, err := attest.NewReviewEmitter(signer, schema)
	if err != nil {
		t.Fatal(err)
	}
	emission, err := emitter.Emit(attest.ReviewInput{
		Subjects: subjects,
		Reviewers: []attest.Reviewer{
			{Identity: "bob@semver-trust.test", Class: "human", Verdict: "approved"},
		},
		PullRequest:   "https://forge.semver-trust.test/release/pull/3",
		MergeStrategy: "merge",
		Timestamp:     pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	return emission
}

// bobAttestationRegistry writes a temp attestation-signer registry enrolling
// bob's vendored public key for the attestation namespace — deliberately a
// SEPARATE registry from the commit-signing one (ADR-022: "may commit" does
// not imply "may attest").
func bobAttestationRegistry(t *testing.T) string {
	t.Helper()
	pub, err := os.ReadFile(filepath.Join(cryptoVendorDir(t), "keys", "human-bob.pub"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "attestation_signers")
	line := "bob@semver-trust.test namespaces=\"" + attest.Namespace + "\" " + strings.TrimSpace(string(pub)) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// rangeSHAs resolves FROM..TO to its commit SHAs.
func rangeSHAs(t *testing.T, repo, from, to string) []string {
	t.Helper()
	rcs, err := vcs.Range(repo, from, to)
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	shas := make([]string, 0, len(rcs))
	for _, rc := range rcs {
		shas = append(shas, rc.Hash)
	}
	return shas
}

func commitsBySigner(commits []CommitReport) map[string]CommitReport {
	m := map[string]CommitReport{}
	for _, c := range commits {
		m[c.Signer] = c
	}
	return m
}
