// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"fmt"

	"github.com/semver-trust/semver-trust-go/evidence"
	"github.com/semver-trust/semver-trust-go/internal/version"
)

// Blast is the qualitative blast-radius score (§6.2). The spec deliberately
// defines no numeric formula — false precision invites gaming — so the score
// arrives here already mapped from its pluggable inputs.
type Blast uint8

const (
	BlastLow Blast = iota
	BlastModerate
	BlastHigh
)

// ParseBlast parses the §6.2 score vocabulary ("low", "moderate", "high").
func ParseBlast(s string) (Blast, error) {
	switch s {
	case "low":
		return BlastLow, nil
	case "moderate":
		return BlastModerate, nil
	case "high":
		return BlastHigh, nil
	default:
		return 0, fmt.Errorf("invalid blast score %q (want low|moderate|high)", s)
	}
}

// String returns the §6.2 form of the score.
func (b Blast) String() string {
	switch b {
	case BlastLow:
		return "low"
	case BlastModerate:
		return "moderate"
	case BlastHigh:
		return "high"
	default:
		return "unknown"
	}
}

// Channel is the release channel a decision selects (§6.4, §7.1).
type Channel uint8

const (
	// ChannelClean — the plain version; default resolvers adopt it.
	ChannelClean Channel = iota
	// ChannelPrerelease — the trust-suffixed pre-release channel; opt-in by
	// construction.
	ChannelPrerelease
)

// String returns the vector-facing name of the channel.
func (c Channel) String() string {
	switch c {
	case ChannelClean:
		return "clean"
	case ChannelPrerelease:
		return "prerelease"
	default:
		return "unknown"
	}
}

// DecideInputs are the two independent inputs of a release decision (§6) and
// the policy that arbitrates them: the evidence ceiling side (effective
// trust, blast score) and the semantic floor side (differ availability, the
// §6.1 floor, the claimed bump), plus the previous release tag and the
// trust-suffix iteration for this cut.
type DecideInputs struct {
	Effective Level
	Blast     Blast
	Strategy  Strategy

	// Threshold is the policy's minimum effective trust level for the clean
	// channel (§6.2, ADR-032). It is applied as a hard gate BEFORE the
	// blast/differ table: a release whose Effective is below Threshold cannot
	// enter the clean channel regardless of blast score or differ evidence.
	// The zero value (T0) is a no-op gate — no release is below T0 — so a
	// caller that does not set it gets the pre-ADR-032 table-only behavior.
	Threshold Level

	// DifferAvailable reports whether a compatibility differ exists for the
	// ecosystem. When false, SemanticFloor comes from declared intent
	// (§6.1(2)) and the §6.4 "differ proof required" cells cannot be
	// satisfied.
	DifferAvailable bool
	SemanticFloor   evidence.Bump
	ClaimedBump     evidence.Bump

	// Current is the previous release tag — a clean §7.1 version, possibly
	// component-prefixed. The decision bumps its core.
	Current version.Version

	// Iteration is the trust-suffix iteration for this cut (≥ 1); re-cuts at
	// the same core version and level increment it (§7.2).
	Iteration uint64
}

// Decision is the outcome: the channel, the final bump (the semantic floor
// is honored unconditionally, so it is max(claim, floor)), and the exact
// §7.1 tag. Under StrategyInflate a cell that would demote escalates
// instead: Escalate is set and Version/bump are unspecified, because the
// escalation target (MINOR vs MAJOR) is a policy choice the spec does not
// pin (§6.3).
type Decision struct {
	Channel  Channel
	Bump     evidence.Bump
	Version  version.Version
	Escalate bool
}

// Cell is a §6.4 decision-table entry: the clean channel is available
// unconditionally, conditioned on a differ proof for PATCH claims,
// conditioned on a differ proof for any claim (the T1/low cell), or
// unavailable.
type Cell uint8

const (
	CellClean Cell = iota
	CellDifferPatch
	CellDifferAny
	CellPrerelease
)

// String returns a short human-readable form of the cell, the vocabulary
// `policy explain` renders.
func (c Cell) String() string {
	switch c {
	case CellClean:
		return "clean"
	case CellDifferPatch:
		return "differ proof (patch)"
	case CellDifferAny:
		return "differ proof (any)"
	case CellPrerelease:
		return "pre-release"
	default:
		return "unknown"
	}
}

// decisionTable is the §6.4 default decision table (illustrative policy;
// rows T0-T3, columns low/moderate/high).
var decisionTable = [4][3]Cell{
	T0: {CellPrerelease, CellPrerelease, CellPrerelease},
	T1: {CellDifferAny, CellPrerelease, CellPrerelease},
	T2: {CellClean, CellDifferPatch, CellPrerelease},
	T3: {CellClean, CellClean, CellDifferPatch},
}

// DecisionCell is the read-only view of the §6.4 default decision table that
// Decide runs: the cell for effective trust l at blast score b. It exists so
// a renderer (`policy explain`) can show the table in effect without
// duplicating it.
func DecisionCell(l Level, b Blast) (Cell, error) {
	if l > T3 || b > BlastHigh {
		return 0, fmt.Errorf("decision cell: invalid inputs (level %d, blast %d)", l, b)
	}
	return decisionTable[l][b], nil
}

// Decide runs the §6.4 default decision table with the §6.3 strategy and
// renders the §7.1 tag. Where the table requires a differ proof and none is
// available, the cell resolves to the pre-release channel — honest
// degradation (§1.1): less verification tooling means lower provable trust.
func Decide(in DecideInputs) (Decision, error) {
	if in.Current.Trust != nil || len(in.Current.Pre) > 0 {
		return Decision{}, fmt.Errorf("decide: current version %s is not a clean release tag", in.Current)
	}
	if in.Iteration < 1 {
		return Decision{}, fmt.Errorf("decide: iteration %d out of range (starts at 1, §7.1)", in.Iteration)
	}
	if in.Effective > T3 || in.Blast > BlastHigh || in.Threshold > T3 {
		return Decision{}, fmt.Errorf("decide: invalid inputs (effective %d, blast %d, threshold %d)", in.Effective, in.Blast, in.Threshold)
	}

	// The semantic floor is honored unconditionally (§10 step 8): the final
	// bump is the larger of the claim and the floor.
	bump := in.ClaimedBump
	if in.SemanticFloor > bump {
		bump = in.SemanticFloor
	}

	// The accountability threshold is a hard gate applied before the
	// blast/differ table (§6.2, ADR-032): below it, the clean channel is
	// unavailable no matter what the table cell says.
	belowThreshold := in.Effective < in.Threshold

	c := decisionTable[in.Effective][in.Blast]
	differNeeded := c == CellDifferAny || (c == CellDifferPatch && bump == evidence.BumpPatch)
	demoted := belowThreshold || c == CellPrerelease || (differNeeded && !in.DifferAvailable)

	if in.Strategy == StrategyInflate {
		if demoted {
			return Decision{Channel: ChannelClean, Escalate: true}, nil
		}
		return Decision{Channel: ChannelClean, Bump: bump, Version: bumpCore(in.Current, bump)}, nil
	}

	v := bumpCore(in.Current, bump)
	if demoted {
		v.Trust = &version.TrustSuffix{Level: uint8(in.Effective), Iteration: in.Iteration}
		return Decision{Channel: ChannelPrerelease, Bump: bump, Version: v}, nil
	}
	return Decision{Channel: ChannelClean, Bump: bump, Version: v}, nil
}

// bumpCore applies a bump to the core of a clean version, keeping its
// component path.
func bumpCore(v version.Version, b evidence.Bump) version.Version {
	out := version.Version{Component: v.Component}
	switch b {
	case evidence.BumpMajor:
		out.Major = v.Major + 1
	case evidence.BumpMinor:
		out.Major, out.Minor = v.Major, v.Minor+1
	default:
		out.Major, out.Minor, out.Patch = v.Major, v.Minor, v.Patch+1
	}
	return out
}
