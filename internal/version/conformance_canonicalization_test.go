// SPDX-License-Identifier: Apache-2.0

package version

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The ADR-036 version-state canonicalization vectors, consumed from the
// ADR-021 vendored copy (conformance/vendor/, digest-pinned by
// conformance/manifest.json). Each carries a carried-forward version-state
// object and the semver-trust-version-state-json v0.2 digest an emitter MUST
// produce and a verifier MUST reproduce. This proves StateDigest computes
// byte-for-byte the same JCS+SHA-256 the spec oracle (check-conformance.py)
// pins.

type canonVectorFile struct {
	SpecVersion string        `json:"spec_version"`
	Vectors     []canonVector `json:"vectors"`
}

type canonVector struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Inputs struct {
		State map[string]any `json:"state"`
	} `json:"inputs"`
	Expected struct {
		Digest struct {
			SHA256 string `json:"sha256"`
		} `json:"digest"`
	} `json:"expected"`
}

func loadCanonVectors(t *testing.T) canonVectorFile {
	t.Helper()
	path := os.Getenv("SEMVER_TRUST_CANON_VECTORS")
	if path == "" {
		for _, candidate := range []string{
			filepath.Join("testdata", "version-state-canonicalization.json"),
			filepath.Join("..", "..", "conformance", "vendor", "version-state-canonicalization.json"),
		} {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		t.Fatal("conformance vectors absent: conformance/vendor/version-state-canonicalization.json missing (refresh via scripts/sync-conformance.py)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading vectors %q: %v", path, err)
	}
	// UseNumber keeps integers as their JSON literal so re-encoding reproduces
	// the oracle's bytes exactly (a float64 detour is fine for these small
	// integers, but json.Number is the faithful path).
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var vf canonVectorFile
	if err := dec.Decode(&vf); err != nil {
		t.Fatalf("parsing vectors %q: %v", path, err)
	}
	return vf
}

func TestConformanceVersionStateCanonicalization(t *testing.T) {
	vf := loadCanonVectors(t)
	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "version_state_canonicalization" {
			continue
		}
		seen++
		got, err := StateDigest(vec.Inputs.State)
		if err != nil {
			t.Fatalf("%s: StateDigest: %v", vec.ID, err)
		}
		if got != vec.Expected.Digest.SHA256 {
			t.Errorf("%s: digest = %s, want %s (JCS+SHA-256 diverges from the oracle)", vec.ID, got, vec.Expected.Digest.SHA256)
		}
	}
	if seen == 0 {
		t.Fatal("no version_state_canonicalization vectors found")
	}
}

// Canonicalization is deterministic and independent of input key order: the
// same logical object always digests to the same value.
func TestStateDigestDeterministicAndOrderIndependent(t *testing.T) {
	a := map[string]any{"b": "2", "a": "1", "nested": map[string]any{"y": 2, "x": 1}}
	b := map[string]any{"a": "1", "nested": map[string]any{"x": 1, "y": 2}, "b": "2"}
	da, err := StateDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := StateDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Errorf("digest depends on input key order: %s != %s", da, db)
	}
	// A changed value changes the digest.
	c := map[string]any{"a": "1", "nested": map[string]any{"x": 1, "y": 3}, "b": "2"}
	dc, err := StateDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	if dc == da {
		t.Error("digest unchanged after a value change")
	}
}

// The digest boundary fails closed: values outside the JCS-safe JSON value tree
// (a struct — encoding/json would serialize its fields in declaration order, not
// JCS lexicographic order — or a float — Go's float serialization is not
// guaranteed JCS-compliant) are rejected, at any nesting depth, rather than
// silently producing a non-canonical digest.
func TestStateDigestRejectsNonCanonicalInput(t *testing.T) {
	type notCanonical struct {
		B string
		A string
	}
	cases := map[string]map[string]any{
		"top-level struct value":    {"x": notCanonical{B: "2", A: "1"}},
		"nested struct in a slice":  {"x": []any{map[string]any{"ok": "1"}, notCanonical{}}},
		"float value":               {"x": 1.5},
		"nested float in a map":     {"x": map[string]any{"y": 2.0}},
		"decimal json.Number":       {"x": json.Number("1.5")},
		"exponent json.Number":      {"x": json.Number("1e3")},
		"negative-zero json.Number": {"x": json.Number("-0")},
	}
	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := StateDigest(state); err == nil {
				t.Error("StateDigest accepted a non-canonical value; want a fail-closed error")
			}
		})
	}

	// The allowed domain still works: nested maps/slices, strings, ints,
	// json.Number, bool, and nil.
	ok := map[string]any{
		"s": "x", "n": 3, "jn": json.Number("7"), "neg": json.Number("-3"), "zero": json.Number("0"),
		"b": true, "nul": nil,
		"arr": []any{1, "two", map[string]any{"k": false}},
	}
	if _, err := StateDigest(ok); err != nil {
		t.Errorf("StateDigest rejected a valid canonical object: %v", err)
	}
}
