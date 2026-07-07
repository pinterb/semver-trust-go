// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

func TestParseTrustVersions(t *testing.T) {
	tests := []struct {
		tag       string
		component string
		major     uint64
		minor     uint64
		patch     uint64
		level     uint8
		iteration uint64
		trust     bool // true = has a trust suffix; false = clean
	}{
		{"v1.4.0-t1.1", "", 1, 4, 0, 1, 1, true},
		{"auth/v2.0.0-t0.3", "auth", 2, 0, 0, 0, 3, true},
		{"pkg/common/v0.9.0", "pkg/common", 0, 9, 0, 0, 0, false},
		{"v1.0.0", "", 1, 0, 0, 0, 0, false},
		{"v1.0.0-t0.1", "", 1, 0, 0, 0, 1, true},
		{"v1.0.0-t3.1", "", 1, 0, 0, 3, 1, true},
		{"v1.0.0-t2.10", "", 1, 0, 0, 2, 10, true},
	}
	for _, tc := range tests {
		v, err := Parse(tc.tag)
		if err != nil {
			t.Errorf("Parse(%q): unexpected error: %v", tc.tag, err)
			continue
		}
		if v.Kind() != KindTrust {
			t.Errorf("Parse(%q): kind = %v, want trust_version", tc.tag, v.Kind())
		}
		if v.Component != tc.component || v.Major != tc.major || v.Minor != tc.minor || v.Patch != tc.patch {
			t.Errorf("Parse(%q): core = %q %d.%d.%d, want %q %d.%d.%d",
				tc.tag, v.Component, v.Major, v.Minor, v.Patch, tc.component, tc.major, tc.minor, tc.patch)
		}
		switch {
		case tc.trust && v.Trust == nil:
			t.Errorf("Parse(%q): want trust suffix, got none", tc.tag)
		case tc.trust && (v.Trust.Level != tc.level || v.Trust.Iteration != tc.iteration):
			t.Errorf("Parse(%q): trust = t%d.%d, want t%d.%d",
				tc.tag, v.Trust.Level, v.Trust.Iteration, tc.level, tc.iteration)
		case !tc.trust && v.Trust != nil:
			t.Errorf("Parse(%q): want clean, got trust suffix", tc.tag)
		}
	}
}

func TestParsePlainVersions(t *testing.T) {
	tests := []struct {
		tag string
		pre string
	}{
		{"v1.4.0-rc.1", "rc.1"},
		{"v1.0.0-alpha", "alpha"},
		{"v2.0.0-beta.11", "beta.11"},
		{"svc/v1.0.0-rc.2", "rc.2"},
		{"v1.0.0-t.1", "t.1"},        // bare "t" is not trust-shaped
		{"v1.0.0-trust.1", "trust.1"}, // "trust" is not t+digits
	}
	for _, tc := range tests {
		v, err := Parse(tc.tag)
		if err != nil {
			t.Errorf("Parse(%q): unexpected error: %v", tc.tag, err)
			continue
		}
		if v.Kind() != KindPlain {
			t.Errorf("Parse(%q): kind = %v, want plain_version", tc.tag, v.Kind())
		}
		if got := joinPre(v); got != tc.pre {
			t.Errorf("Parse(%q): prerelease = %q, want %q", tc.tag, got, tc.pre)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	// Trust-shaped-but-malformed tags must fail closed, never fall through to
	// plain_version; malformed cores and build metadata are rejected too.
	invalid := []string{
		"v1.4.0-t10.1", // two-digit level
		"v1.4.0-t1",    // missing iteration
		"v1.4.0-t1.0",  // iteration zero
		"v1.4.0-t4.1",  // level out of range
		"v1.4.0-t1.1.2", // trailing identifier on a trust suffix
		"v1.4",         // core not MAJOR.MINOR.PATCH
		"1.4.0",        // missing "v"
		"v01.2.3",      // leading zero in core
		"v1.2.3-",      // empty pre-release
		"v1.2.3+build", // build metadata rejected
		"/v1.0.0",      // empty component
		"",             // empty tag
	}
	for _, tag := range invalid {
		if v, err := Parse(tag); err == nil {
			t.Errorf("Parse(%q): want error, got %+v", tag, v)
		}
	}
}

func TestParseFailClosedStaysInvalid(t *testing.T) {
	// A trust-shaped-but-malformed suffix is a valid raw SemVer version, so the
	// distinction between fail-closed (Parse) and raw comparison (parseSemver)
	// is load-bearing: parseSemver accepts what Parse rejects.
	const tag = "v1.4.0-t10.1"
	if _, err := Parse(tag); err == nil {
		t.Errorf("Parse(%q): want invalid, got success", tag)
	}
	if _, err := parseSemver("1.4.0-t10.1"); err != nil {
		t.Errorf("parseSemver(1.4.0-t10.1): want raw-SemVer success, got %v", err)
	}
}

func TestParseFormatRoundTrip(t *testing.T) {
	tags := []string{
		"v1.0.0",
		"v1.4.0-t1.1",
		"auth/v2.0.0-t0.3",
		"pkg/common/v0.9.0",
		"v1.0.0-t2.10",
		"v1.4.0-rc.1",
		"svc/v1.2.3-beta.2",
	}
	for _, tag := range tags {
		v, err := Parse(tag)
		if err != nil {
			t.Errorf("Parse(%q): %v", tag, err)
			continue
		}
		if got := v.String(); got != tag {
			t.Errorf("round-trip: Parse(%q).String() = %q", tag, got)
		}
	}
}

func joinPre(v Version) string {
	out := ""
	for i, id := range v.Pre {
		if i > 0 {
			out += "."
		}
		out += id
	}
	return out
}
