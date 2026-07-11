// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"errors"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/version"
)

// mustParseAll strict-parses each tag, failing the test on any rejection. It
// builds the exact version slices the Latest/Next tables operate on.
func mustParseAll(t *testing.T, tags ...string) []version.Version {
	t.Helper()
	vs := make([]version.Version, 0, len(tags))
	for _, tag := range tags {
		v, err := version.Parse(tag)
		if err != nil {
			t.Fatalf("version.Parse(%q) unexpected error: %v", tag, err)
		}
		vs = append(vs, v)
	}
	return vs
}

// TestParseTags covers the plain-mode filter and its always-surfaced rejected
// count. Fed the donor's six-tag fixture set, strict §7.1 parsing keeps only the
// two v-prefixed clean versions; the bare forms (the donor coerced these under
// lenient Masterminds) and the leading-zero 0.1.0-alpha.01 are all rejected.
func TestParseTags(t *testing.T) {
	tests := []struct {
		name         string
		raw          []string
		wantValid    []string
		wantRejected int
	}{
		{
			name: "donor six-tag fixture set",
			raw: []string{
				"0.0.2",
				"0.1.0-alpha.0.beta",
				"0.1.0-alpha.01",
				"0.1.1-beta.0",
				"v0.0.1",
				"v0.1.0",
			},
			wantValid:    []string{"v0.0.1", "v0.1.0"},
			wantRejected: 4,
		},
		{
			name:         "all valid",
			raw:          []string{"v1.0.0", "v1.2.3-rc.1"},
			wantValid:    []string{"v1.0.0", "v1.2.3-rc.1"},
			wantRejected: 0,
		},
		{
			name:         "all rejected",
			raw:          []string{"nonsense", "1.2", "v1.2.3+build"},
			wantValid:    nil,
			wantRejected: 3,
		},
		{
			name:         "empty input",
			raw:          nil,
			wantValid:    nil,
			wantRejected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			valid, rejected := ParseTags(tc.raw)
			if rejected != tc.wantRejected {
				t.Errorf("rejected = %d, want %d", rejected, tc.wantRejected)
			}
			gotStrs := make([]string, len(valid))
			for i, v := range valid {
				gotStrs[i] = v.String()
			}
			if len(gotStrs) != len(tc.wantValid) {
				t.Fatalf("valid = %v, want %v", gotStrs, tc.wantValid)
			}
			for i := range tc.wantValid {
				if gotStrs[i] != tc.wantValid[i] {
					t.Errorf("valid[%d] = %q, want %q", i, gotStrs[i], tc.wantValid[i])
				}
			}
		})
	}
}

func TestLatest(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{"unsorted core versions", []string{"v0.0.1", "v0.1.0", "v0.0.2"}, "v0.1.0"},
		{"release outranks its pre-release", []string{"v1.0.0-rc.1", "v1.0.0"}, "v1.0.0"},
		{"single element", []string{"v2.3.4"}, "v2.3.4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Latest(mustParseAll(t, tc.in...))
			if err != nil {
				t.Fatalf("Latest error: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("Latest = %q, want %q", got.String(), tc.want)
			}
		})
	}

	t.Run("empty is ErrNoVersions", func(t *testing.T) {
		if _, err := Latest(nil); !errors.Is(err, ErrNoVersions) {
			t.Fatalf("Latest(nil) err = %v, want ErrNoVersions", err)
		}
	})

	t.Run("does not mutate input order", func(t *testing.T) {
		in := mustParseAll(t, "v0.0.1", "v0.1.0", "v0.0.2")
		_, _ = Latest(in)
		if in[0].String() != "v0.0.1" || in[1].String() != "v0.1.0" || in[2].String() != "v0.0.2" {
			t.Fatalf("Latest mutated its input: %v", []string{in[0].String(), in[1].String(), in[2].String()})
		}
	})

	t.Run("cross-component input errors", func(t *testing.T) {
		mixed := mustParseAll(t, "auth/v1.0.0", "v1.0.0")
		if _, err := Latest(mixed); err == nil {
			t.Fatal("expected a cross-component error, got nil")
		}
	})
}

// TestNext covers the node-semver bump on the latest version and the donor's
// 0.0.0 bootstrap for a tagless repository. Increment semantics themselves are
// pinned in internal/version; here we assert Next picks the latest and seeds
// correctly.
func TestNext(t *testing.T) {
	tests := []struct {
		name  string
		in    []string
		level string
		preid string
		want  string
	}{
		{"patch on latest", []string{"v0.0.1", "v0.1.0", "v0.0.2"}, "patch", "", "v0.1.1"},
		{"minor on latest", []string{"v0.1.0"}, "minor", "", "v0.2.0"},
		{"major on latest", []string{"v0.1.0"}, "major", "", "v1.0.0"},
		{"prerelease on latest", []string{"v0.1.0"}, "prerelease", "", "v0.1.1-0"},
		{"premajor with preid", []string{"v1.2.3"}, "premajor", "alpha", "v2.0.0-alpha.0"},
		{"bootstrap patch on empty", nil, "patch", "", "v0.0.1"},
		{"bootstrap minor on empty", nil, "minor", "", "v0.1.0"},
		{"bootstrap major on empty", nil, "major", "", "v1.0.0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := version.ToReleaseType(tc.level)
			if err != nil {
				t.Fatalf("ToReleaseType(%q): %v", tc.level, err)
			}
			got, err := Next(mustParseAll(t, tc.in...), rt, tc.preid)
			if err != nil {
				t.Fatalf("Next error: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("Next(%v, %s, %q) = %q, want %q", tc.in, tc.level, tc.preid, got.String(), tc.want)
			}
		})
	}
}
