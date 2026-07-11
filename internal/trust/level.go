// SPDX-License-Identifier: Apache-2.0

package trust

// Level is the scalar trust level T0-T3 (§3.1): a count of independent
// accountable humans bound to a change, with one intermediate rung (T1) for
// agent corroboration. Levels order accountability, not risk (§1.1
// Principle 6).
type Level uint8

const (
	// T0 — no accountable human: agent-authored (or mixed/ambiguous
	// authorship) with no independent review.
	T0 Level = iota
	// T1 — no accountable human, but independently agent-reviewed (§3.3).
	T1
	// T2 — exactly one accountable human, in either role.
	T2
	// T3 — two distinct accountable humans: verified author identity ≠
	// verified reviewer identity.
	T3
)

// String returns the vector-facing name of the level ("T0".."T3").
func (l Level) String() string {
	switch l {
	case T0:
		return "T0"
	case T1:
		return "T1"
	case T2:
		return "T2"
	case T3:
		return "T3"
	default:
		return "unknown"
	}
}

// Authorship is the derived authorship class of a commit (§3.2), determined
// by the verified signer identity class combined with provenance trailers.
type Authorship uint8

const (
	// AuthorshipAgent — authored under a machine identity, or self-asserted
	// as agent-produced.
	AuthorshipAgent Authorship = iota
	// AuthorshipMixed — self-asserted mixed human+agent authorship (§4.1).
	AuthorshipMixed
	// AuthorshipAmbiguous — the signer identity class and the provenance
	// trailers conflict, or required trailers are absent under a policy that
	// mandates them (§3.2 note 1).
	AuthorshipAmbiguous
	// AuthorshipHuman — a verified human identity standing behind the commit
	// as an accountability assertion (§4.2).
	AuthorshipHuman
)

// String returns the vector-facing name of the authorship class.
func (a Authorship) String() string {
	switch a {
	case AuthorshipAgent:
		return "agent"
	case AuthorshipMixed:
		return "mixed"
	case AuthorshipAmbiguous:
		return "ambiguous"
	case AuthorshipHuman:
		return "human"
	default:
		return "unknown"
	}
}

// Review is the derived review class of a commit (§3.2). The classifier only
// ever produces ReviewNone, ReviewAgentIndependent, or ReviewHumanDistinct —
// a non-qualifying review collapses to ReviewNone. ReviewHumanSameIdentity
// exists so the level function can be exercised against the full §3.2 matrix,
// where self-review appears as an explicit input class.
type Review uint8

const (
	// ReviewNone — no qualifying review.
	ReviewNone Review = iota
	// ReviewAgentIndependent — an agent review meeting all three §3.3
	// independence conditions.
	ReviewAgentIndependent
	// ReviewHumanDistinct — a verified human reviewer distinct from the
	// author.
	ReviewHumanDistinct
	// ReviewHumanSameIdentity — a human reviewing their own commit, which
	// does not count as review (§3.2 note 2).
	ReviewHumanSameIdentity
)

// String returns the vector-facing name of the review class.
func (r Review) String() string {
	switch r {
	case ReviewNone:
		return "none"
	case ReviewAgentIndependent:
		return "agent_independent"
	case ReviewHumanDistinct:
		return "human_distinct"
	case ReviewHumanSameIdentity:
		return "human_same_identity"
	default:
		return "unknown"
	}
}

// AssignLevel maps an authorship × review pair to its trust level per the
// §3.2 matrix. The matrix reduces to the Appendix B accountability invariant:
// level = f(count of accountable humans, agent corroboration). Accountable
// humans are the author (if human) and a distinct human reviewer; self-review
// contributes nothing (§3.2 note 2); independent agent review lifts the
// zero-human case from T0 to T1.
func AssignLevel(a Authorship, r Review) Level {
	humans := 0
	if a == AuthorshipHuman {
		humans++
	}
	if r == ReviewHumanDistinct {
		humans++
	}
	switch {
	case humans >= 2:
		return T3
	case humans == 1:
		return T2
	case r == ReviewAgentIndependent:
		return T1
	default:
		return T0
	}
}
