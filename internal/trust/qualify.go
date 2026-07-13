// SPDX-License-Identifier: Apache-2.0

package trust

// ReviewQualification carries the qualified-review facts a v0.2 review
// attestation binds (spec repository ADR-031): only an approved review that is
// active at merge, bound to the final reviewed revision (or final diff), from a
// canonical actor distinct from the author, and — for agent review — from a
// separate execution context, raises trust. Actors are canonical: two
// credentials that map to one actor (key rotation, aliases) count once.
//
// This is the §4.3/ADR-031 semantics exercised by the review-qualification
// conformance suite. The production verify path still consumes review/v0.1
// (verdict pre-gated at the parse layer, ADR-031 verdict half); migrating it to
// build ReviewQualification from review/v0.2 predicates and the policy actor
// map is tracked in semver-trust-go#76.
type ReviewQualification struct {
	ReviewerClass IdentityClass
	// ReviewerActor and AuthorActor are canonical actor identities (§4.2, §9).
	ReviewerActor string
	AuthorActor   string

	Verdict          string // approved | changes_requested | commented
	ApprovalState    string // active | stale | withdrawn | dismissed
	EffectiveAtMerge bool

	// Coverage is "final_revision" or "final_diff"; the latter binds a
	// squash/rebase pre-rewrite diff (ApprovedDiff) to the result (ResultDiff).
	Coverage         string
	ApprovedRevision string
	FinalRevision    string
	ApprovedDiff     string
	ResultDiff       string

	// SeparateContext reports separate agent execution state (§3.3 condition 1);
	// only consulted for agent review.
	SeparateContext bool
	// PostApprovalChange reports a source/target/merge change after approval.
	PostApprovalChange bool
	SignedAttestation  bool
}

// QualifyReview applies the ADR-031 gate sequence to a review covering a commit
// of the given authorship, returning the review class and, when the review does
// not qualify, a stable reason. A non-qualifying review contributes ReviewNone;
// the commit still classifies from its authorship (a human author alone is T2).
func QualifyReview(author Authorship, q ReviewQualification) (Review, string) {
	if !q.SignedAttestation {
		return ReviewNone, "unsigned_attestation"
	}
	if q.Verdict != "approved" {
		return ReviewNone, "verdict_not_approved"
	}
	if q.ApprovalState != "active" || !q.EffectiveAtMerge {
		return ReviewNone, "approval_not_active"
	}

	// The approval must bind the content that merged: the final revision, or —
	// for a captured squash/rebase — the final diff.
	diffBound := q.Coverage == "final_diff" && q.ApprovedDiff != "" && q.ApprovedDiff == q.ResultDiff
	if q.Coverage == "final_diff" {
		if !diffBound {
			return ReviewNone, "revision_mismatch"
		}
	} else if q.ApprovedRevision != q.FinalRevision {
		return ReviewNone, "revision_mismatch"
	}

	// A post-approval change disqualifies unless the approved diff was captured
	// and equals the result (§4.3.5 squash/rebase capture).
	if q.PostApprovalChange && !diffBound {
		return ReviewNone, "post_approval_change"
	}

	switch q.ReviewerClass {
	case IdentityAgent:
		// Agent review qualifies for T1 only from a distinct canonical actor in
		// a separate execution context (§3.3).
		if !q.SeparateContext || q.ReviewerActor == q.AuthorActor {
			return ReviewNone, "agent_not_independent"
		}
		return ReviewAgentIndependent, ""
	case IdentityHuman:
		// Distinctness is evaluated on canonical actors. A human reviewing their
		// own human-authored commit adds no second human (§3.2 note 2, ADR-025);
		// for agent/mixed/ambiguous authorship the same human is the first — and
		// only — accountable human, so it still counts.
		if author == AuthorshipHuman && q.ReviewerActor == q.AuthorActor {
			return ReviewNone, "same_canonical_actor"
		}
		return ReviewHumanDistinct, ""
	default:
		return ReviewNone, "unknown_reviewer_class"
	}
}
