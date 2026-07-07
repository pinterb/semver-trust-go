// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

func TestCompareOrdering(t *testing.T) {
	// Each pair is (lower, higher); Compare must report -1 and its inverse +1.
	pairs := [][2]string{
		{"1.0.0-alpha", "1.0.0-alpha.1"},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta"},
		{"1.0.0-alpha.beta", "1.0.0-beta"},
		{"1.0.0-beta.2", "1.0.0-beta.11"},
		{"1.0.0-rc.1", "1.0.0"},
		{"1.4.0-rc.1", "1.4.0-t1.1"},
		{"1.0.0-t2.2", "1.0.0-t2.10"},
		{"1.0.0-t10.1", "1.0.0-t2.1"}, // lexical: "t10" < "t2"
		{"1.0.0-t0.5", "1.0.0-t2.1"},
		{"1.0.0-1", "1.0.0-rc"}, // numeric below alphanumeric
		{"1.0.0", "1.0.1"},
		{"1.0.0-t3.1", "1.0.1-t0.1"}, // core dominates the suffix
	}
	for _, p := range pairs {
		lo := mustSemver(t, p[0])
		hi := mustSemver(t, p[1])

		if got, err := Compare(lo, hi); err != nil || got != -1 {
			t.Errorf("Compare(%q, %q) = %d, %v; want -1", p[0], p[1], got, err)
		}
		if got, err := Compare(hi, lo); err != nil || got != 1 {
			t.Errorf("Compare(%q, %q) = %d, %v; want 1", p[1], p[0], got, err)
		}
		if got, err := Compare(lo, lo); err != nil || got != 0 {
			t.Errorf("Compare(%q, %q) = %d, %v; want 0", p[0], p[0], got, err)
		}
	}
}

func TestCompareTrustAndSemverAgree(t *testing.T) {
	// A trust version parsed via the tag grammar must compare identically to the
	// same version parsed as raw SemVer, since the suffix is ordinary identifiers.
	tagV := mustParse(t, "v1.0.0-t2.10")
	rawV := mustSemver(t, "1.0.0-t2.10")
	if got, err := Compare(tagV, rawV); err != nil || got != 0 {
		t.Errorf("trust vs raw compare = %d, %v; want 0", got, err)
	}
}

func TestCompareDifferentComponentsErrors(t *testing.T) {
	a := mustParse(t, "auth/v1.0.0")
	b := mustParse(t, "billing/v1.0.0")
	if _, err := Compare(a, b); err == nil {
		t.Error("Compare across component paths: want error, got nil")
	}
}

func TestSort(t *testing.T) {
	raw := []string{"1.0.0", "1.0.0-rc.1", "1.0.0-t1.1", "1.0.0-alpha", "1.0.1"}
	want := []string{"1.0.0-alpha", "1.0.0-rc.1", "1.0.0-t1.1", "1.0.0", "1.0.1"}

	vs := make([]Version, len(raw))
	for i, s := range raw {
		vs[i] = mustSemver(t, s)
	}
	if err := Sort(vs); err != nil {
		t.Fatalf("Sort: %v", err)
	}
	for i, v := range vs {
		if got := v.String(); got != "v"+want[i] {
			t.Errorf("Sort[%d] = %q, want %q", i, got, "v"+want[i])
		}
	}
}

func TestSortDifferentComponentsErrors(t *testing.T) {
	vs := []Version{mustParse(t, "auth/v1.0.0"), mustParse(t, "billing/v1.0.0")}
	if err := Sort(vs); err == nil {
		t.Error("Sort across component paths: want error, got nil")
	}
}

func mustParse(t *testing.T, tag string) Version {
	t.Helper()
	v, err := Parse(tag)
	if err != nil {
		t.Fatalf("Parse(%q): %v", tag, err)
	}
	return v
}

func mustSemver(t *testing.T, s string) Version {
	t.Helper()
	v, err := parseSemver(s)
	if err != nil {
		t.Fatalf("parseSemver(%q): %v", s, err)
	}
	return v
}
