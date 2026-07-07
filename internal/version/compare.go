// SPDX-License-Identifier: Apache-2.0

package version

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Compare orders a and b by SemVer 2.0.0 §11 precedence, returning -1, 0, or +1.
//
// Core fields compare numerically; a clean release outranks any pre-release of
// the same core; pre-release identifiers compare left to right, numerics
// numerically and below alphanumerics, alphanumerics ASCII-lexically, and a
// shorter set of identifiers ranks lower when it is a prefix of the longer. The
// trust suffix participates as the ordinary identifiers "t<level>" (alphanumeric)
// and "<iteration>" (numeric), so t10 sorts below t2 and iteration 2 below 10.
//
// Component paths partition the ordering (§7.1): comparing versions with
// different component paths is a caller error and returns a non-nil error with a
// zero result.
func Compare(a, b Version) (int, error) {
	if a.Component != b.Component {
		return 0, fmt.Errorf("cannot compare versions across component paths %q and %q", a.Component, b.Component)
	}
	return compareWithinComponent(a, b), nil
}

// Sort orders vs ascending by SemVer precedence. Every element must share the
// same component path; otherwise Sort returns an error and leaves vs unmodified.
func Sort(vs []Version) error {
	if len(vs) < 2 {
		return nil
	}
	for i := 1; i < len(vs); i++ {
		if vs[i].Component != vs[0].Component {
			return fmt.Errorf("cannot sort versions across component paths %q and %q", vs[0].Component, vs[i].Component)
		}
	}
	sort.SliceStable(vs, func(i, j int) bool {
		return compareWithinComponent(vs[i], vs[j]) < 0
	})
	return nil
}

// compareWithinComponent applies §11 precedence, assuming the component paths
// have already been reconciled by the caller.
func compareWithinComponent(a, b Version) int {
	if c := cmpUint(a.Major, b.Major); c != 0 {
		return c
	}
	if c := cmpUint(a.Minor, b.Minor); c != 0 {
		return c
	}
	if c := cmpUint(a.Patch, b.Patch); c != 0 {
		return c
	}
	return comparePrerelease(a.prereleaseIdents(), b.prereleaseIdents())
}

// prereleaseIdents returns the pre-release identifiers that participate in
// precedence: the trust suffix expanded to ["t<level>", "<iteration>"], the
// plain pre-release identifiers, or nil for a clean release.
func (v Version) prereleaseIdents() []string {
	if v.Trust != nil {
		return []string{
			"t" + strconv.FormatUint(uint64(v.Trust.Level), 10),
			strconv.FormatUint(v.Trust.Iteration, 10),
		}
	}
	return v.Pre
}

// comparePrerelease implements the SemVer §11 pre-release rules.
func comparePrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0: // a is a clean release; it outranks any pre-release
		return 1
	case len(b) == 0:
		return -1
	}

	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if c := compareIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	// Identical up to the shorter length: fewer identifiers ranks lower.
	return cmpInt(len(a), len(b))
}

// compareIdent compares two pre-release identifiers: numerics numerically,
// alphanumerics lexically, and a numeric below an alphanumeric.
func compareIdent(a, b string) int {
	an, bn := isNumericIdent(a), isNumericIdent(b)
	switch {
	case an && bn:
		return compareNumeric(a, b)
	case an:
		return -1
	case bn:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

// isNumericIdent reports whether id is a SemVer numeric identifier (all digits).
func isNumericIdent(id string) bool {
	if id == "" {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return true
}

// compareNumeric compares two numeric identifiers without overflow. Valid SemVer
// numerics carry no leading zero, so the wider string is the larger number and
// equal widths compare lexically.
func compareNumeric(a, b string) int {
	if len(a) != len(b) {
		return cmpInt(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
