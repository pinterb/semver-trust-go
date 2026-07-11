// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// pinnedEpoch is the fixture verification instant (docs/conformance-crypto-
// fixtures.md §3): the injected clock every fixture verifies against.
var pinnedEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// The release fixture is the end-to-end happy path (§10 steps 1–7): a signed
// range whose own trust floors to T0, verified against the vendored registry
// at the pinned epoch. The JSON report is the acceptance surface.
func TestVerifyReleaseSucceeds(t *testing.T) {
	fixtures := buildFixtures(t)
	repo := filepath.Join(fixtures, "release")

	report, err := Verify(Options{
		RepoPath:           repo,
		From:               "v0.1.0",
		To:                 "main",
		PolicyPath:         ".semver-trust/policy.toml",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Two commits: alice human→T2, ci-bot agent→T0 (the Provenance: agent
	// trailer classifies agent authorship even under a human-enrolled signer).
	if len(report.Commits) != 2 {
		t.Fatalf("commits = %d, want 2", len(report.Commits))
	}
	bySigner := map[string]CommitReport{}
	for _, c := range report.Commits {
		bySigner[c.Signer] = c
	}
	assertCommit(t, bySigner["alice@semver-trust.test"], "T2", "human", "none")
	assertCommit(t, bySigner["ci-bot@semver-trust.test"], "T0", "agent", "none")

	// Own trust floors to T0 for the single (default) scope the range touches.
	if len(report.Scopes) != 1 || report.Scopes[0].Scope != "default" {
		t.Fatalf("scopes = %+v, want a single default scope", report.Scopes)
	}
	if got := report.Scopes[0].OwnFloor; got != "T0" {
		t.Errorf("default own floor = %s, want T0", got)
	}

	// Effective trust with the "none" adapter equals own trust, self-sourced.
	if report.Propagation.Adapter != "none" {
		t.Errorf("adapter = %q, want none", report.Propagation.Adapter)
	}

	// Policy digest is the SHA-256 of the in-tree policy file (§8.1).
	wantDigest := fileSHA256(t, filepath.Join(repo, ".semver-trust", "policy.toml"))
	if report.Policy.Digest != wantDigest {
		t.Errorf("policy digest = %s, want %s", report.Policy.Digest, wantDigest)
	}

	// Meta-path check passed: the policy file is untouched inside v0.1.0..main.
	if !report.MetaPath.Passed || len(report.MetaPath.Violations) != 0 {
		t.Errorf("meta-path = %+v, want passed with no violations", report.MetaPath)
	}

	// Declared-intent semantic floor: both range commits are fix: → patch.
	if report.Evidence.SemanticFloor != "patch" || report.Evidence.SemanticFloorSource != "declared_intent" {
		t.Errorf("semantic floor = %s (%s), want patch (declared_intent)",
			report.Evidence.SemanticFloor, report.Evidence.SemanticFloorSource)
	}
}

// A range that includes the setup commit (root..main) contains a T2 commit
// touching .semver-trust/** while meta-paths require T3 → abort outright at the
// §5.4 check, not demote (§5.4, Appendix A step 5).
func TestVerifyMetaPathBelowRequiredAborts(t *testing.T) {
	fixtures := buildFixtures(t)
	repo := filepath.Join(fixtures, "release")

	_, err := Verify(Options{
		RepoPath:           repo,
		From:               "", // root..main includes the policy-authoring setup commit
		To:                 "main",
		PolicyPath:         ".semver-trust/policy.toml",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	})
	assertAbortStep(t, err, stepMetaPath)
}

// A repository whose TO tree carries no policy file aborts at step 1 (load
// policy): the policy is read from the tree, and its absence is fatal.
func TestVerifyMissingPolicyAborts(t *testing.T) {
	fixtures := buildFixtures(t)
	repo := filepath.Join(fixtures, "signed-history")

	_, err := Verify(Options{
		RepoPath:           repo,
		To:                 "main",
		PolicyPath:         ".semver-trust/policy.toml",
		AllowedSignersPath: allowedSignersPath(t),
		VerifyTime:         pinnedEpoch,
	})
	assertAbortStep(t, err, stepLoadPolicy)
}

// Signature-abort fixtures carry no policy in their trees, so they exercise the
// pipeline (verifyWith) with an injected minimal policy: an unverifiable commit
// aborts at step 3 with its signature-verification sentinel — unverifiable is
// never T0 (§5.2). Each sentinel is distinct by construction.
func TestVerifySignatureAborts(t *testing.T) {
	fixtures := buildFixtures(t)
	pol := minimalPolicy(t)

	cases := []struct {
		repo     string
		sentinel error
	}{
		{"unknown-signer", vcs.ErrUnknownSigner},
		{"tampered", vcs.ErrInvalidSignature},
		{"gpg-signed", vcs.ErrUnsupportedKeyFamily},
	}
	for _, tc := range cases {
		t.Run(tc.repo, func(t *testing.T) {
			_, err := verifyWith(Options{
				RepoPath:           filepath.Join(fixtures, tc.repo),
				To:                 "main",
				AllowedSignersPath: allowedSignersPath(t),
				VerifyTime:         pinnedEpoch,
			}, pol)
			assertAbortStep(t, err, stepSignature)
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("error = %v, want sentinel %v", err, tc.sentinel)
			}
		})
	}
}

func assertCommit(t *testing.T, c CommitReport, level, authorship, review string) {
	t.Helper()
	if c.Level != level || c.Authorship != authorship || c.Review != review {
		t.Errorf("commit %s: got %s/%s/%s, want %s/%s/%s",
			c.Short, c.Level, c.Authorship, c.Review, level, authorship, review)
	}
}

func assertAbortStep(t *testing.T, err error, step string) {
	t.Helper()
	var ab *AbortError
	if !errors.As(err, &ab) {
		t.Fatalf("error = %v, want *AbortError", err)
	}
	if ab.Step != step {
		t.Errorf("abort step = %q, want %q", ab.Step, step)
	}
}

func minimalPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	pol, err := policy.Parse([]byte(`[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T3"
`))
	if err != nil {
		t.Fatalf("minimal policy: %v", err)
	}
	return pol
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
