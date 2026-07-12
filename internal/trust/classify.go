// SPDX-License-Identifier: Apache-2.0

package trust

// IdentityClass is the class of a verified identity (§4.2): human identities
// come from an allowed-signers registry or an OIDC identity mapped to a
// person; agent identities are machine identities (CI workload identities,
// bot accounts, dedicated agent service identities).
type IdentityClass uint8

const (
	// IdentityHuman — a verified identity that maps to a person.
	IdentityHuman IdentityClass = iota
	// IdentityAgent — a verified machine identity.
	IdentityAgent
)

// String returns the vector-facing name of the identity class.
func (c IdentityClass) String() string {
	switch c {
	case IdentityHuman:
		return "human"
	case IdentityAgent:
		return "agent"
	default:
		return "unknown"
	}
}

// Provenance trailer values (§4.1). The empty string means the trailer is
// absent.
const (
	ProvenanceHuman = "human"
	ProvenanceAgent = "agent"
	ProvenanceMixed = "mixed"
)

// CommitFacts are the verified facts about a commit that classification
// consumes. Everything here is established upstream: Signer by signature
// verification against injected trust material (§4.2, ADR-018), Review by
// locating and cryptographically verifying the covering review attestation
// (§4.3). A commit whose signature or required attestations cannot be
// verified never reaches classification — verification aborts instead
// (unverifiable ≠ T0, §5.2).
type CommitFacts struct {
	// Signer is the verified signer's identity class (§4.2), the primary
	// authorship signal.
	Signer IdentityClass

	// Provenance is the commit's Provenance trailer value ("human", "agent",
	// "mixed"), or empty when the trailer is absent. Trailers are
	// self-asserted and advisory: they refine classification but never
	// override the signer identity class (§4.1).
	Provenance string

	// TrailersRequired reports whether policy mandates provenance trailers
	// on this commit (§4.1, policy [trailers] require).
	TrailersRequired bool

	// Review carries the verified review facts, or nil when there is no
	// review.
	Review *ReviewFacts
}

// ReviewFacts are the verified facts about a commit's review, extracted from
// a review attestation (§4.3).
type ReviewFacts struct {
	// Reviewer is the verified reviewer's identity class.
	Reviewer IdentityClass

	// ReviewerIdentity and SignerIdentity are the verified identities used
	// for the same-identity tests (§3.2 note 2, §3.3 condition 2).
	// SignerIdentity is the COMMIT's verified signer principal — not
	// necessarily a counted human author: after an honest Provenance: agent
	// trailer, authorship classifies agent and the signer is nobody's
	// author (ADR-025; the old name AuthorIdentity caused exactly that
	// conflation).
	ReviewerIdentity string
	SignerIdentity   string

	// SeparateContext reports whether the reviewing agent ran in a separate
	// execution context with no shared conversational or working state with
	// the author (§3.3 condition 1). It is only consulted for agent review.
	SeparateContext bool

	// SignedAttestation reports whether the review produced a signed review
	// attestation (§3.3 condition 3, §4.3).
	SignedAttestation bool
}

// Classify derives the authorship and review classes from verified commit
// facts and assigns the §3.2 level.
func Classify(f CommitFacts) (Authorship, Review, Level) {
	a := classifyAuthorship(f)
	r := classifyReview(a, f.Review)
	return a, r, AssignLevel(a, r)
}

// classifyAuthorship applies §3.2 note 1 and the §4.1 trailer rules. The
// governing principle: trailers are self-asserted, so they may concede agent
// involvement but can never raise a commit above what the verified signer
// identity class supports. Unverifiable claims of human authorship are
// treated as absent, and every conflict floors to the agent row via
// AuthorshipAmbiguous.
func classifyAuthorship(f CommitFacts) Authorship {
	switch f.Provenance {
	case "":
		// Absent trailer: ambiguous under a mandating policy (§3.2 note 1);
		// otherwise the signer identity class alone governs.
		if f.TrailersRequired {
			return AuthorshipAmbiguous
		}
		if f.Signer == IdentityHuman {
			return AuthorshipHuman
		}
		return AuthorshipAgent
	case ProvenanceHuman:
		// A human claim needs a human signer behind it; on a machine
		// identity the conflict is ambiguous (§4.1 rule 1).
		if f.Signer == IdentityHuman {
			return AuthorshipHuman
		}
		return AuthorshipAmbiguous
	case ProvenanceAgent:
		// Conceding agent authorship is honest under any signer: a human
		// signer running an agent locally is exactly the §4.2 local-use case
		// the trailer exists to surface.
		return AuthorshipAgent
	case ProvenanceMixed:
		return AuthorshipMixed
	default:
		// An unrecognized trailer value is an unverifiable claim; it floors
		// like any other conflict.
		return AuthorshipAmbiguous
	}
}

// classifyReview collapses non-qualifying reviews to ReviewNone, and is
// authorship-aware per ADR-025: the self-review exclusion prevents one human
// from counting twice, never from counting once. Agent review qualifies only
// when all three §3.3 independence conditions hold — including a reviewer
// identity distinct from the signer, since self-checking corroborates
// nothing. Human review requires a signed attestation (§4.3: an unattested
// review is an unverifiable claim, treated as absent); the same-identity
// exclusion applies only when the authorship class is human — for agent-,
// mixed-, or ambiguous-authored commits no human author is counted, so a
// same-identity human review adds the first accountable human (agent +
// human = T2). Separate execution context is an agent-review condition
// (§3.3(1)) and is not consulted for human review.
func classifyReview(a Authorship, r *ReviewFacts) Review {
	if r == nil || !r.SignedAttestation {
		return ReviewNone
	}
	switch r.Reviewer {
	case IdentityAgent:
		if !r.SeparateContext || r.ReviewerIdentity == r.SignerIdentity {
			return ReviewNone
		}
		return ReviewAgentIndependent
	case IdentityHuman:
		if a == AuthorshipHuman && r.ReviewerIdentity == r.SignerIdentity {
			return ReviewNone
		}
		return ReviewHumanDistinct
	default:
		return ReviewNone
	}
}
