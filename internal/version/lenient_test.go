// SPDX-License-Identifier: Apache-2.0

package version

import (
	"reflect"
	"testing"
)

// TestParseLenient pins the donor-parity coercion (go-semver README /
// Masterminds NewVersion, audit §5.1/§5.9) and the §7.1 fail-closed scoping:
// trust shapes enter only by strict-parsing, never by coercion.
func TestParseLenient(t *testing.T) {
	tests := []struct {
		tag       string
		canonical string // expected Canonical(); "" means invalid
		coerced   bool
	}{
		// Donor README anchors: semver 2.1 v1.0.1 v3 4.x 5.12.
		{"2.1", "2.1.0", true},
		{"v1.0.1", "1.0.1", false}, // §7.1-valid as-is
		{"v3", "3.0.0", true},
		{"4.x", "", false},
		{"5.12", "5.12.0", true},

		// Short and v-less forms.
		{"1", "1.0.0", true},
		{"0.0.2", "0.0.2", true},
		{"1.2-5", "1.2.0-5", true}, // audit §5.1
		{"5.12.1-rc.0", "5.12.1-rc.0", true},

		// Strict §7.1 tags pass through uncoerced, trust versions included.
		{"v1.2.3", "1.2.3", false},
		{"v1.4.0-rc.1", "1.4.0-rc.1", false},
		{"v1.4.0-t2.1", "1.4.0-t2.1", false},
		{"auth/v2.1.3", "auth/2.1.3", false},

		// Build metadata: donor accepted it; out of grammar, so coerced.
		{"1.2.3+build.7", "1.2.3+build.7", true},
		{"v1.2.3+sha-abc", "1.2.3+sha-abc", true},
		{"1.2.3+", "", false},
		{"1.2.3+meta..7", "", false},
		{"1.2.3+meta_7", "", false},

		// Masterminds edges (audit §5.9): wide numerics and leading zeros in
		// the core coerce; leading-zero numeric pre-release identifiers do not.
		{"1.2.2147483648", "1.2.2147483648", true},
		{"01.2.3", "1.2.3", true},
		{"0.1.0-alpha.01", "", false},
		{"1.2.3-alpha.-1", "1.2.3-alpha.-1", true},

		// Trust shapes fail closed everywhere (§7.1): malformed suffixes and
		// trust suffixes on out-of-grammar forms are never coerced to plain.
		{"v1.0.0-t10.1", "", false},
		{"v1.0.0-t1", "", false},
		{"v1.0.0-t1.0", "", false},
		{"v1.0.0-t4.1", "", false},
		{"1.0-t2.1", "", false},
		{"1.0.0-t2.1", "", false},
		{"v1.0.0-t2.1+build", "", false},

		// Not coercible at all.
		{"", "", false},
		{"v", "", false},
		{"foo", "", false},
		{"1.2.3.4", "", false},
		{"1.2.3-", "", false},
		{"auth/1.2.3", "", false}, // component paths must be §7.1-valid
	}
	for _, tc := range tests {
		got, err := ParseLenient(tc.tag)
		if tc.canonical == "" {
			if err == nil {
				t.Errorf("ParseLenient(%q) = %+v, want error", tc.tag, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLenient(%q): unexpected error %v", tc.tag, err)
			continue
		}
		if c := got.Canonical(); c != tc.canonical {
			t.Errorf("ParseLenient(%q).Canonical() = %q, want %q", tc.tag, c, tc.canonical)
		}
		if got.Coerced != tc.coerced {
			t.Errorf("ParseLenient(%q).Coerced = %v, want %v", tc.tag, got.Coerced, tc.coerced)
		}
	}
}

// A strict-valid tag lenient-parses to exactly its strict parse, so the
// lenient layer cannot drift from §7.1 on the tags the grammar admits.
func TestParseLenientAgreesWithStrict(t *testing.T) {
	for _, tag := range []string{"v1.2.3", "v0.1.0-t3.2", "v1.4.0-rc.1", "pkg/common/v0.9.0-t0.3"} {
		strict, err := Parse(tag)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tag, err)
		}
		lenient, err := ParseLenient(tag)
		if err != nil {
			t.Fatalf("ParseLenient(%q): %v", tag, err)
		}
		if !reflect.DeepEqual(lenient.Version, strict) || lenient.Coerced || lenient.Build != nil {
			t.Errorf("ParseLenient(%q) = %+v, want uncoerced %+v", tag, lenient, strict)
		}
	}
}

// A coerced result never carries a trust suffix: the only door into the
// lenient-valid set for a trust version is strict Parse.
func TestParseLenientNeverCoercesTrust(t *testing.T) {
	for _, tag := range []string{"2.1", "v3", "1.2-5", "1.2.3+build", "5.12.1-rc.0"} {
		got, err := ParseLenient(tag)
		if err != nil {
			t.Fatalf("ParseLenient(%q): %v", tag, err)
		}
		if got.Version.Trust != nil {
			t.Errorf("ParseLenient(%q) produced a trust suffix %+v", tag, got.Version.Trust)
		}
	}
}
