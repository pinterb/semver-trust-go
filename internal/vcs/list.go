// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"errors"

	"github.com/semver-trust/semver-trust-go/internal/version"
)

// ErrNoVersions is returned by Latest when there are no valid versions to
// choose a maximum from. Next does not return it: an empty input bootstraps
// from 0.0.0 instead.
var ErrNoVersions = errors.New("no valid versions")

// ParseTags strict-parses each raw tag through version.Parse and returns the
// versions that parsed, in input order, together with the count that did not.
//
// This is the plain-mode filter: invalid tags are dropped so a caller can list
// or bump the valid ones, but the rejected count is always returned so the drop
// is never silent (go-semver audit §5.2 — lenient filtering is allowed in plain
// mode, silent dropping is not). Parsing is strict (§7.1): a bare or v-less form
// such as 0.0.2, and a leading-zero pre-release such as 0.1.0-alpha.01, are
// rejected, not coerced. Lenient coercion is GO-041.
func ParseTags(raw []string) (valid []version.Version, rejected int) {
	valid = make([]version.Version, 0, len(raw))
	for _, tag := range raw {
		v, err := version.Parse(tag)
		if err != nil {
			rejected++
			continue
		}
		valid = append(valid, v)
	}
	return valid, rejected
}

// Latest returns the highest version in vs by SemVer 2.0.0 precedence. It
// returns ErrNoVersions when vs is empty, and propagates version.Sort's
// cross-component error when the versions do not all share one component path.
// vs is not modified.
func Latest(vs []version.Version) (version.Version, error) {
	if len(vs) == 0 {
		return version.Version{}, ErrNoVersions
	}
	sorted := append([]version.Version(nil), vs...)
	if err := version.Sort(sorted); err != nil {
		return version.Version{}, err
	}
	return sorted[len(sorted)-1], nil
}

// Next returns the version that follows the latest of vs when incremented by
// rt, with preid seeding the pre-release identifier for the pre* levels.
//
// When vs is empty it bootstraps from 0.0.0 (the donor's --default behavior:
// the default version participates as a candidate), so a tagless repository
// yields v0.0.1 for a patch bump. version.Increment supplies the node-semver
// semantics and rejects a trust suffix on the latest version — a trust re-cut
// is NextIteration/WithLevel (§7.2), not a node-semver bump. Cross-component
// input surfaces version.Sort's error via Latest.
func Next(vs []version.Version, rt version.ReleaseType, preid string) (version.Version, error) {
	base := version.Version{} // 0.0.0, empty component — the bootstrap seed.
	if len(vs) > 0 {
		latest, err := Latest(vs)
		if err != nil {
			return version.Version{}, err
		}
		base = latest
	}
	return version.Increment(base, rt, preid)
}
