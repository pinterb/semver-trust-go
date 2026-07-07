// SPDX-License-Identifier: Apache-2.0

package version

import (
	"math/rand"
	"reflect"
	"strconv"
	"testing"
)

// TestParseFormatIdentity is the GO-020 property: parse∘format is identity over
// generated valid tags. It generates Versions directly across the §7.1-valid
// space — clean, trust-suffixed, and plain — and asserts Parse(v.String())
// reproduces v exactly.
//
// The generator is seeded from a constant; it uses no wall-clock time.
// Generation is grounded in the §7.1 grammar rather than the org tag ruleset
// regex: that regex is the platform gate and is deliberately looser than the
// canonical parser (it admits build metadata and trust-shaped-malformed
// suffixes, both of which Parse rejects), so it is not a source of "valid"
// inputs for this property.
func TestParseFormatIdentity(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5e3ec0de))

	const iterations = 5000
	for i := 0; i < iterations; i++ {
		v := genVersion(rng)

		// Invariant: a generated plain pre-release must never begin with a
		// trust-shaped identifier, or Parse would reclassify it as a trust
		// version and the round-trip would fail on the Version even while the
		// string round-trips.
		if len(v.Pre) > 0 && isTrustShaped(v.Pre[0]) {
			t.Fatalf("generator produced trust-shaped plain pre-release: %q", v.Pre[0])
		}

		s := v.String()
		got, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error: %v", s, err)
		}
		if !reflect.DeepEqual(got, v) {
			t.Fatalf("round-trip mismatch for %q: got %#v, want %#v", s, got, v)
		}
		if got.String() != s {
			t.Fatalf("format∘parse mismatch: Parse(%q).String() = %q", s, got.String())
		}
	}
}

func genVersion(rng *rand.Rand) Version {
	v := Version{
		Component: genComponent(rng),
		Major:     genNumber(rng),
		Minor:     genNumber(rng),
		Patch:     genNumber(rng),
	}
	switch rng.Intn(3) {
	case 0:
		// clean
	case 1:
		v.Trust = &TrustSuffix{
			Level:     uint8(rng.Intn(int(MaxLevel) + 1)),
			Iteration: uint64(rng.Intn(100000)) + 1,
		}
	case 2:
		v.Pre = genPlainPrerelease(rng)
	}
	return v
}

func genComponent(rng *rand.Rand) string {
	if rng.Intn(2) == 0 {
		return ""
	}
	segments := rng.Intn(3) + 1
	out := ""
	for i := 0; i < segments; i++ {
		if i > 0 {
			out += "/"
		}
		out += genSegment(rng)
	}
	return out
}

func genSegment(rng *rand.Rand) string {
	const first = "abcdefghijklmnopqrstuvwxyz"
	const rest = "abcdefghijklmnopqrstuvwxyz0123456789-_"
	n := rng.Intn(6) + 1
	b := make([]byte, n)
	b[0] = first[rng.Intn(len(first))]
	for i := 1; i < n; i++ {
		b[i] = rest[rng.Intn(len(rest))]
	}
	return string(b)
}

// safeAlpha are pre-release first identifiers that are valid SemVer and never
// trust-shaped (t followed only by digits).
var safeAlpha = []string{"rc", "alpha", "beta", "dev", "snapshot", "x", "next", "pre"}

func genPlainPrerelease(rng *rand.Rand) []string {
	n := rng.Intn(3) + 1
	ids := make([]string, n)
	ids[0] = safeAlpha[rng.Intn(len(safeAlpha))]
	for i := 1; i < n; i++ {
		if rng.Intn(2) == 0 {
			ids[i] = strconv.FormatUint(genNumber(rng), 10) // numeric, no leading zero
		} else {
			ids[i] = safeAlpha[rng.Intn(len(safeAlpha))]
		}
	}
	return ids
}

func genNumber(rng *rand.Rand) uint64 {
	return uint64(rng.Intn(1_000_000))
}
