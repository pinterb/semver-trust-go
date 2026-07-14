// SPDX-License-Identifier: Apache-2.0

package trust

import "testing"

// TestQualifyReviewOracleSurface exercises the ADR-031 decision surface the
// vendored review-qualification vectors do not currently cover, so QualifyReview
// mirrors the spec oracle rather than merely passing the shipped vectors: the
// credential↔actor binding, the squash/rebase-only final_diff flow, that any
// post-approval change disqualifies (no captured-diff exception), and the
// diff-mismatch and unknown-coverage reasons.
func TestQualifyReviewOracleSurface(t *testing.T) {
	// A qualified human review of an agent-authored commit (the accept base).
	base := ReviewQualification{
		ReviewerClass:     IdentityHuman,
		ReviewerActor:     "actor:human:alice",
		AuthorActor:       "actor:agent:writer",
		CredentialActor:   "actor:human:alice",
		Verdict:           "approved",
		ApprovalState:     "active",
		EffectiveAtMerge:  true,
		Coverage:          "final_revision",
		ApprovedRevision:  "rev:final",
		FinalRevision:     "rev:final",
		SignedAttestation: true,
	}
	if r, reason := QualifyReview(AuthorshipAgent, base); r != ReviewHumanDistinct || reason != "" {
		t.Fatalf("base = %s/%q, want human_distinct/none", r, reason)
	}

	cases := []struct {
		name    string
		mutate  func(q *ReviewQualification)
		wantR   Review
		wantRsn string
	}{
		{"credential maps to a different actor", func(q *ReviewQualification) {
			q.CredentialActor = "actor:human:mallory"
		}, ReviewNone, "credential_actor_mismatch"},
		{"final_diff on a native merge is unsupported", func(q *ReviewQualification) {
			q.Coverage = "final_diff"
			q.MergeStrategy = "merge"
			q.CaptureMode = "native"
			q.ApprovedDiff, q.ResultDiff = "sha256:d", "sha256:d"
		}, ReviewNone, "unsupported_final_diff_flow"},
		{"final_diff without pre-rewrite capture is unsupported", func(q *ReviewQualification) {
			q.Coverage = "final_diff"
			q.MergeStrategy = "squash"
			q.CaptureMode = "native"
			q.ApprovedDiff, q.ResultDiff = "sha256:d", "sha256:d"
		}, ReviewNone, "unsupported_final_diff_flow"},
		{"captured squash with mismatched diffs", func(q *ReviewQualification) {
			q.Coverage = "final_diff"
			q.MergeStrategy = "squash"
			q.CaptureMode = "pre_rewrite"
			q.ApprovedDiff, q.ResultDiff = "sha256:a", "sha256:b"
		}, ReviewNone, "diff_mismatch"},
		{"any post-approval change disqualifies, even with a bound final_diff", func(q *ReviewQualification) {
			q.Coverage = "final_diff"
			q.MergeStrategy = "squash"
			q.CaptureMode = "pre_rewrite"
			q.ApprovedDiff, q.ResultDiff = "sha256:d", "sha256:d"
			q.PostApprovalChange = true
		}, ReviewNone, "post_approval_change"},
		{"unknown coverage mode", func(q *ReviewQualification) {
			q.Coverage = "eyeballed"
		}, ReviewNone, "unknown_coverage"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			q := base
			tt.mutate(&q)
			r, reason := QualifyReview(AuthorshipAgent, q)
			if r != tt.wantR || reason != tt.wantRsn {
				t.Errorf("= %s/%q, want %s/%q", r, reason, tt.wantR, tt.wantRsn)
			}
		})
	}
}
