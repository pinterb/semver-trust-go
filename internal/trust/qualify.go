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
	// ReviewerActor and AuthorActor are canonical actor identities (§4.2, §9);
	// CredentialActor is the actor the signing credential maps to and MUST
	// equal ReviewerActor (an asserted reviewer cannot borrow a credential
	// mapping to a different actor).
	ReviewerActor   string
	AuthorActor     string
	CredentialActor string

	Verdict          string // approved | changes_requested | commented
	ApprovalState    string // active | stale | withdrawn | dismissed
	EffectiveAtMerge bool

	// Coverage is "final_revision" or "final_diff". final_diff is only valid for
	// a captured squash/rebase flow (MergeStrategy squash|rebase, CaptureMode
	// pre_rewrite) and binds ApprovedDiff to ResultDiff.
	Coverage         string
	ApprovedRevision string
	FinalRevision    string
	ApprovedDiff     string
	ResultDiff       string
	MergeStrategy    string
	CaptureMode      string

	// SeparateContext reports separate agent execution state (§3.3 condition 1);
	// only consulted for agent review.
	SeparateContext bool
	// PostApprovalChange reports a source/target/merge change after approval;
	// any such change disqualifies (a captured squash/rebase carries no
	// post-approval change — its content is bound by the final diff instead).
	PostApprovalChange bool
	SignedAttestation  bool
}

// QualifyReview applies the ADR-031 gate sequence to a review covering a commit
// of the given authorship, returning the review class and, when the review does
// not qualify, a stable reason. A non-qualifying review contributes ReviewNone;
// the commit still classifies from its authorship (a human author alone is T2).
func QualifyReview(author Authorship, q ReviewQualification) (Review, string) {
	if q.Verdict != "approved" {
		return ReviewNone, "verdict_not_approved"
	}
	if q.ApprovalState != "active" || !q.EffectiveAtMerge {
		return ReviewNone, "approval_not_active"
	}
	if !q.SignedAttestation {
		return ReviewNone, "unsigned_attestation"
	}
	if q.CredentialActor != q.ReviewerActor {
		return ReviewNone, "credential_actor_mismatch"
	}
	if q.PostApprovalChange {
		return ReviewNone, "post_approval_change"
	}

	// The approval must bind the content that merged: the final revision, or —
	// only for a captured squash/rebase flow — the final diff.
	switch q.Coverage {
	case "final_revision":
		if q.ApprovedRevision != q.FinalRevision {
			return ReviewNone, "revision_mismatch"
		}
	case "final_diff":
		if (q.MergeStrategy != "squash" && q.MergeStrategy != "rebase") || q.CaptureMode != "pre_rewrite" {
			return ReviewNone, "unsupported_final_diff_flow"
		}
		if q.ApprovedDiff != q.ResultDiff {
			return ReviewNone, "diff_mismatch"
		}
	default:
		return ReviewNone, "unknown_coverage"
	}

	switch q.ReviewerClass {
	case IdentityAgent:
		// Agent review qualifies for T1 only from a distinct canonical actor in
		// a separate execution context (§3.3).
		if q.ReviewerActor == q.AuthorActor || !q.SeparateContext {
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
