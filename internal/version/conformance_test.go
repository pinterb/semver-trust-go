// SPDX-License-Identifier: Apache-2.0

package version

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The conformance vectors are the spec repository's acceptance suite. This smoke
// test consumes them when they are reachable but stays hermetic: the durable,
// version-pinned harness that vendors the vectors is GO-026. Point it at the
// vectors with SEMVER_TRUST_VECTORS, or drop them at testdata/precedence.json;
// absent both, the test skips.

type vectorFile struct {
	SpecVersion string   `json:"spec_version"`
	Vectors     []vector `json:"vectors"`
}

type vector struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Ordered  []string        `json:"ordered"`
	Tag      string          `json:"tag"`
	Expected grammarExpected `json:"expected"`
}

// grammarExpected uses pointers for every nullable field: level 0 is a valid
// trust level and must stay distinct from an absent level (null).
type grammarExpected struct {
	Outcome       string  `json:"outcome"`
	ComponentPath *string `json:"component_path"`
	Core          *string `json:"core"`
	Level         *int    `json:"level"`
	Iteration     *uint64 `json:"iteration"`
	Prerelease    *string `json:"prerelease"`
	Reason        *string `json:"reason"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()

	path := os.Getenv("SEMVER_TRUST_VECTORS")
	if path == "" {
		candidate := filepath.Join("testdata", "precedence.json")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
		}
	}
	if path == "" {
		t.Skip("conformance vectors absent; set SEMVER_TRUST_VECTORS or vendor testdata/precedence.json (GO-026)")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading vectors %q: %v", path, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parsing vectors %q: %v", path, err)
	}
	return vf
}

func TestConformancePrecedence(t *testing.T) {
	vf := loadVectors(t)

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "precedence" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			ordered := make([]Version, len(vec.Ordered))
			for i, s := range vec.Ordered {
				v, err := parseSemver(s)
				if err != nil {
					t.Fatalf("parseSemver(%q): %v", s, err)
				}
				ordered[i] = v
			}

			// The list must be strictly ascending under the comparator.
			for i := 0; i+1 < len(ordered); i++ {
				got, err := Compare(ordered[i], ordered[i+1])
				if err != nil {
					t.Fatalf("Compare(%q, %q): %v", vec.Ordered[i], vec.Ordered[i+1], err)
				}
				if got != -1 {
					t.Errorf("Compare(%q, %q) = %d, want -1", vec.Ordered[i], vec.Ordered[i+1], got)
				}
			}

			// Sorting a reversed copy must reproduce the given order exactly.
			shuffled := make([]Version, len(ordered))
			for i, v := range ordered {
				shuffled[len(ordered)-1-i] = v
			}
			if err := Sort(shuffled); err != nil {
				t.Fatalf("Sort: %v", err)
			}
			for i := range shuffled {
				if shuffled[i].String() != ordered[i].String() {
					t.Errorf("Sort position %d = %q, want %q", i, shuffled[i].String(), ordered[i].String())
				}
			}
		})
	}
	if seen == 0 {
		t.Error("no precedence vectors found")
	}
}

func TestConformanceGrammar(t *testing.T) {
	vf := loadVectors(t)

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "grammar" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			v, err := Parse(vec.Tag)

			if vec.Expected.Outcome == "invalid" {
				if err == nil {
					t.Fatalf("Parse(%q): want invalid, got %+v", vec.Tag, v)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): want %s, got error: %v", vec.Tag, vec.Expected.Outcome, err)
			}
			if got := v.Kind().String(); got != vec.Expected.Outcome {
				t.Errorf("Parse(%q): outcome = %s, want %s", vec.Tag, got, vec.Expected.Outcome)
			}

			assertComponent(t, vec, v)
			assertCore(t, vec, v)
			assertTrust(t, vec, v)
			assertPrerelease(t, vec, v)
		})
	}
	if seen == 0 {
		t.Error("no grammar vectors found")
	}
}

func assertComponent(t *testing.T, vec vector, v Version) {
	t.Helper()
	want := ""
	if vec.Expected.ComponentPath != nil {
		want = *vec.Expected.ComponentPath
	}
	if v.Component != want {
		t.Errorf("Parse(%q): component = %q, want %q", vec.Tag, v.Component, want)
	}
}

func assertCore(t *testing.T, vec vector, v Version) {
	t.Helper()
	if vec.Expected.Core == nil {
		return
	}
	got := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if got != *vec.Expected.Core {
		t.Errorf("Parse(%q): core = %q, want %q", vec.Tag, got, *vec.Expected.Core)
	}
}

func assertTrust(t *testing.T, vec vector, v Version) {
	t.Helper()
	switch {
	case vec.Expected.Level == nil:
		if v.Trust != nil {
			t.Errorf("Parse(%q): got trust suffix, want none", vec.Tag)
		}
	case v.Trust == nil:
		t.Errorf("Parse(%q): want level %d, got no trust suffix", vec.Tag, *vec.Expected.Level)
	default:
		if int(v.Trust.Level) != *vec.Expected.Level {
			t.Errorf("Parse(%q): level = %d, want %d", vec.Tag, v.Trust.Level, *vec.Expected.Level)
		}
		if vec.Expected.Iteration != nil && v.Trust.Iteration != *vec.Expected.Iteration {
			t.Errorf("Parse(%q): iteration = %d, want %d", vec.Tag, v.Trust.Iteration, *vec.Expected.Iteration)
		}
	}
}

func assertPrerelease(t *testing.T, vec vector, v Version) {
	t.Helper()
	if vec.Expected.Prerelease == nil {
		if len(v.Pre) > 0 {
			t.Errorf("Parse(%q): got prerelease %q, want none", vec.Tag, joinPre(v))
		}
		return
	}
	if got := joinPre(v); got != *vec.Expected.Prerelease {
		t.Errorf("Parse(%q): prerelease = %q, want %q", vec.Tag, got, *vec.Expected.Prerelease)
	}
}
