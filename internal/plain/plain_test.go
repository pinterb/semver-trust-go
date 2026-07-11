// SPDX-License-Identifier: Apache-2.0

package plain

import (
	"errors"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/version"
)

// The donor README's argument set, the behavior-parity anchor for the whole
// plain-mode surface: semver 2.1 v1.0.1 v3 4.x 5.12.
var donorArgs = []string{"2.1", "v1.0.1", "v3", "4.x", "5.12"}

func canonicals(vs []version.Lenient) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.Canonical()
	}
	return out
}

// Donor anchor: the valid set is everything but 4.x, and sorting yields
// "1.0.1 2.1.0 3.0.0 5.12.0".
func TestClassifySortDonorAnchor(t *testing.T) {
	entries := Classify(donorArgs)
	SortEntries(entries)

	var got []string
	for _, e := range entries {
		if e.Err == nil {
			got = append(got, e.Val.Canonical())
		}
	}
	want := "1.0.1 2.1.0 3.0.0 5.12.0"
	if s := strings.Join(got, " "); s != want {
		t.Errorf("sorted valid set = %q, want %q", s, want)
	}

	// The invalid entry is flagged, last, and carries its reason — not dropped.
	last := entries[len(entries)-1]
	if last.Raw != "4.x" || last.Err == nil {
		t.Errorf("last entry = %+v, want flagged-invalid 4.x", last)
	}
}

func TestValidRejectedCount(t *testing.T) {
	valid, rejected := Valid(append([]string{"0.1.0-alpha.01", "foo"}, donorArgs...))
	if rejected != 3 { // 0.1.0-alpha.01, foo, 4.x
		t.Errorf("rejected = %d, want 3", rejected)
	}
	if len(valid) != 4 {
		t.Errorf("valid = %v, want 4 entries", canonicals(valid))
	}
}

func TestLatest(t *testing.T) {
	valid, _ := Valid(donorArgs)
	latest, err := Latest(valid)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got := latest.Canonical(); got != "5.12.0" {
		t.Errorf("Latest = %q, want %q", got, "5.12.0")
	}

	if _, err := Latest(nil); !errors.Is(err, ErrNoVersions) {
		t.Errorf("Latest(nil) error = %v, want ErrNoVersions", err)
	}
}

// A trust version enters the set by strict parse and participates in
// precedence: a clean release at the same core outranks it, and a trust
// pre-release above every clean tag wins the latest selection.
func TestLatestTrustParticipates(t *testing.T) {
	valid, rejected := Valid([]string{"v1.2.0", "v1.3.0-t2.1", "1.2.5"})
	if rejected != 0 {
		t.Fatalf("rejected = %d, want 0", rejected)
	}
	latest, err := Latest(valid)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if latest.Version.Trust == nil || latest.Canonical() != "1.3.0-t2.1" {
		t.Errorf("Latest = %q, want the trust tag 1.3.0-t2.1", latest.Canonical())
	}
}

func TestLatestCrossComponentErrors(t *testing.T) {
	valid, _ := Valid([]string{"v1.0.0", "auth/v2.0.0"})
	if _, err := Latest(valid); err == nil {
		t.Error("Latest across component paths succeeded, want error (§7.1 partitioned ordering)")
	}
}

// Donor increment anchors from the README, run over the donor argument set.
func TestNextDonorAnchors(t *testing.T) {
	tests := []struct {
		name  string
		raw   []string
		level string
		preid string
		want  string
	}{
		{"prepatch preid=rc on donor set", donorArgs, "prepatch", "rc", "5.12.1-rc.0"},
		{"prerelease on rc.0", []string{"5.12.1-rc.0"}, "prerelease", "rc", "5.12.1-rc.1"},
		{"tagless bootstrap", nil, "patch", "", "0.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := version.ToReleaseType(tc.level)
			if err != nil {
				t.Fatalf("ToReleaseType(%q): %v", tc.level, err)
			}
			valid, _ := Valid(tc.raw)
			next, err := Next(valid, rt, tc.preid)
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			if got := (version.Lenient{Version: next}).Canonical(); got != tc.want {
				t.Errorf("Next = %q, want %q", got, tc.want)
			}
		})
	}
}

// Next fails closed when the latest is trust-suffixed: no skipping, no
// node-semver bump of a trust version — the error points at the §7.2 path.
func TestNextRefusesTrustLatest(t *testing.T) {
	valid, _ := Valid([]string{"v1.2.0", "v1.3.0-t2.1"})
	rt, _ := version.ToReleaseType("patch")
	_, err := Next(valid, rt, "")
	if err == nil {
		t.Fatal("Next on a trust-suffixed latest succeeded, want refusal")
	}
	if !strings.Contains(err.Error(), "trust suffix") || !strings.Contains(err.Error(), "release") {
		t.Errorf("error %q should name the trust suffix and point at release operations", err)
	}
}
