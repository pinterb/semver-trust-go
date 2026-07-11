// SPDX-License-Identifier: Apache-2.0

// Package plain implements the zero-configuration plain-mode tag operations
// (GO-041): the go-semver donor surface — classify, sort, latest, next — over
// the lenient-valid tag set version.ParseLenient admits. It reads no policy
// and touches no trust machinery beyond refusing it: per the maintainer
// decision of 2026-07-07, out-of-grammar tags are tolerated here for display
// parity, but anything trust-shaped stays under the §7.1 fail-closed contract
// — a trust version enters the set only by strict-parsing, participates in
// precedence for latest selection, and makes Next refuse rather than be
// node-semver-bumped.
package plain

import (
	"errors"
	"fmt"
	"sort"

	"github.com/semver-trust/semver-trust-go/internal/version"
)

// ErrNoVersions is returned by Latest when the valid set is empty. Next does
// not return it: an empty input bootstraps from 0.0.0 (audit §5.4).
var ErrNoVersions = errors.New("no valid versions")

// Entry is one raw tag classified for plain-mode display: either a
// lenient-valid value or the parse error that rejected it.
type Entry struct {
	// Raw is the tag as enumerated from the repository or command line.
	Raw string
	// Val is the lenient parse result; meaningful only when Err is nil.
	Val version.Lenient
	// Err is the rejection reason for an invalid tag, nil otherwise.
	Err error
}

// Classify lenient-parses every raw tag, in input order. Nothing is dropped:
// invalid tags come back as entries carrying their error, so a lister can
// flag them instead of silently discarding (audit §5.2).
func Classify(raw []string) []Entry {
	entries := make([]Entry, len(raw))
	for i, tag := range raw {
		val, err := version.ParseLenient(tag)
		entries[i] = Entry{Raw: tag, Val: val, Err: err}
	}
	return entries
}

// SortEntries orders entries for display: valid entries ascending by
// component path then SemVer precedence (the donor's SortedList order,
// audit §5.3), with invalid entries after them in their input order.
func SortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		switch {
		case a.Err != nil:
			return false // invalid sorts after everything, stably
		case b.Err != nil:
			return true
		}
		if a.Val.Version.Component != b.Val.Version.Component {
			return a.Val.Version.Component < b.Val.Version.Component
		}
		c, _ := version.Compare(a.Val.Version, b.Val.Version) // components equal; no error
		return c < 0
	})
}

// Valid lenient-parses raw and returns the valid values in input order plus
// the count that were rejected, which the caller must surface — the drop is
// never silent (audit §5.2).
func Valid(raw []string) (valid []version.Lenient, rejected int) {
	valid = make([]version.Lenient, 0, len(raw))
	for _, tag := range raw {
		val, err := version.ParseLenient(tag)
		if err != nil {
			rejected++
			continue
		}
		valid = append(valid, val)
	}
	return valid, rejected
}

// Latest returns the highest of vs by SemVer 2.0.0 precedence (build metadata
// does not participate, §10; on a precedence tie the earlier value wins). It
// returns ErrNoVersions on an empty set and version.Compare's error when the
// set spans component paths, which partition the ordering (§7.1).
func Latest(vs []version.Lenient) (version.Lenient, error) {
	if len(vs) == 0 {
		return version.Lenient{}, ErrNoVersions
	}
	best := vs[0]
	for _, v := range vs[1:] {
		c, err := version.Compare(best.Version, v.Version)
		if err != nil {
			return version.Lenient{}, err
		}
		if c < 0 {
			best = v
		}
	}
	return best, nil
}

// Next returns the version that follows the latest of vs when incremented by
// rt with node-semver semantics, preid seeding the pre-release identifier for
// the pre* levels. An empty vs bootstraps from 0.0.0 (the donor's --default
// behavior, audit §5.4). Build metadata on the latest is dropped, exactly as
// the donor's Masterminds increment functions dropped it.
//
// Trust versions participate in the latest selection but are refused as the
// increment base: a trust re-cut is a §7.2 release operation
// (NextIteration/WithLevel via `release`, GO-042), not a node-semver bump, so
// Next fails closed with guidance rather than skipping the tag or bumping it.
func Next(vs []version.Lenient, rt version.ReleaseType, preid string) (version.Version, error) {
	base := version.Version{} // 0.0.0, empty component — the bootstrap seed.
	if len(vs) > 0 {
		latest, err := Latest(vs)
		if err != nil {
			return version.Version{}, err
		}
		if latest.Version.Trust != nil {
			return version.Version{}, fmt.Errorf(
				"latest version %s carries a trust suffix; plain-mode next cannot node-semver-bump it — a trust re-cut is a release operation (§7.2, `semver-trust release`)",
				latest.Version)
		}
		base = latest.Version
	}
	return version.Increment(base, rt, preid)
}
