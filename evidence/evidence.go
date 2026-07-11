// SPDX-License-Identifier: Apache-2.0

// Package evidence is the public evidence-provider seam (spec §6.1-§6.2,
// ADR-011): providers supply the compatibility evidence a release decision
// consumes — first among them the compatibility differ that determines the
// semantic floor.
//
// The seam is deliberately self-contained: implementations outside this
// module reference only this package's types. It is one of the three seams
// kept public (evidence providers, workspace graph adapters, registry
// projections); everything else in this module lives under internal/.
package evidence

import "fmt"

// Bump is a SemVer bump claim: to claim one is to claim what it implies
// (PATCH: drop-in safe; MINOR: additive only; §6.2). As the output of a
// compatibility differ it is the semantic floor — the minimum bump the
// change semantics permit (§6.1).
type Bump uint8

const (
	BumpPatch Bump = iota
	BumpMinor
	BumpMajor
)

// ParseBump parses the vector-facing bump names ("patch", "minor", "major").
func ParseBump(s string) (Bump, error) {
	switch s {
	case "patch":
		return BumpPatch, nil
	case "minor":
		return BumpMinor, nil
	case "major":
		return BumpMajor, nil
	default:
		return 0, fmt.Errorf("invalid bump %q (want patch|minor|major)", s)
	}
}

// String returns the vector-facing name of the bump.
func (b Bump) String() string {
	switch b {
	case BumpPatch:
		return "patch"
	case BumpMinor:
		return "minor"
	case BumpMajor:
		return "major"
	default:
		return "unknown"
	}
}

// CompatDiffer detects public-surface compatibility between two trees of the
// same component and reports the semantic floor (§6.1): a detected breaking
// change forces BumpMajor — no trust level overrides it — additive-only
// changes force BumpMinor, and an unchanged public surface permits
// BumpPatch.
//
// Where no differ exists for an ecosystem, the decision table's "differ
// proof required" cells resolve to the pre-release channel (§6.4): less
// verification tooling means lower provable trust, never equal trust with
// less backing (§1.1, honest degradation). Implementations MUST NOT fetch
// anything over the network.
type CompatDiffer interface {
	// Name is the differ's policy-facing name (§9 [evidence.<ecosystem>]
	// compat).
	Name() string

	// Floor compares the released tree at oldDir against the candidate tree
	// at newDir and returns the semantic floor.
	Floor(oldDir, newDir string) (Bump, error)
}
