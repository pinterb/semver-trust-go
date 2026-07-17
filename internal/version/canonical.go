// SPDX-License-Identifier: Apache-2.0

package version

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
)

// integerJSONNumber matches a JSON integer literal: 0 or an optionally negative
// non-zero integer with no leading zero, no fraction, no exponent, and no -0.
// The ADR-036 object domain is integer-only, and Go's float/decimal
// serialization is not guaranteed JCS-canonical, so a json.Number outside this
// grammar (e.g. "1.5", "1e3") must fail closed.
var integerJSONNumber = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

// This file implements the ADR-036 semver-trust-version-state-json v0.2 profile:
// the carried-forward version state (§7.5/ADR-029) serialized with RFC 8785
// (JSON Canonicalization Scheme) and hashed with SHA-256. The digest is bound as
// a release/v0.2 stateIdentity and re-derived by a verifier to authenticate the
// version-decision chain (§8.1). ADR-036 defines the field set; these functions
// only serialize and digest whatever canonical object the caller supplies.

// CanonicalizeState returns the RFC 8785 (JCS) serialization of a version-state
// object. For this object domain (ASCII keys/strings, integers, bool, null,
// arrays, nested objects — no floats), a sorted-key, minimally separated,
// non-HTML-escaping JSON encoding is byte-identical to JCS, which is exactly
// what encoding/json produces with SetEscapeHTML(false); no JCS dependency is
// required. The spec oracle (check-conformance.py) computes the same bytes, and
// the vendored conformance vectors pin the resulting digests.
//
// This is the digest boundary, so it FAILS CLOSED on any value outside the
// JCS-safe JSON value tree — string-keyed maps, slices, strings, integers,
// json.Number, bool, and nil. Structs are rejected because encoding/json
// preserves struct-field declaration order, not JCS lexicographic member order,
// so a struct would silently produce a non-canonical digest; floats are
// rejected because Go's float serialization is not guaranteed JCS-compliant
// (and the profile is float-free). The caller MUST build the canonical object
// from map[string]any (ADR-036 defines the field set).
func CanonicalizeState(state map[string]any) ([]byte, error) {
	if err := validateCanonical(state); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(state); err != nil {
		return nil, fmt.Errorf("version: canonicalize state: %w", err)
	}
	// Encoder.Encode appends a trailing newline; JCS output carries none.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// validateCanonical recursively rejects any value outside the JCS-safe JSON
// value tree, so a non-canonical or non-reproducible digest can never be
// produced silently (structs, floats, pointers, typed maps, etc. all fail).
func validateCanonical(v any) error {
	switch x := v.(type) {
	case nil, bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return nil
	case json.Number:
		if !integerJSONNumber.MatchString(string(x)) {
			return fmt.Errorf(
				"version: canonicalize state: json.Number %q is not an integer (the profile is integer-only; decimals and exponents are not JCS-canonical)",
				string(x))
		}
		return nil
	case map[string]any:
		for k, val := range x {
			if err := validateCanonical(val); err != nil {
				return fmt.Errorf("at key %q: %w", k, err)
			}
		}
		return nil
	case []any:
		for i, val := range x {
			if err := validateCanonical(val); err != nil {
				return fmt.Errorf("at index %d: %w", i, err)
			}
		}
		return nil
	default:
		return fmt.Errorf(
			"version: canonicalize state: unsupported type %T (the canonical object must be built from map[string]any/[]any/string/integer/bool/null; structs and floats are not JCS-canonical)",
			v)
	}
}

// StateDigest is the lowercase-hex SHA-256 of the canonicalized version state —
// the bare-hex value bound as a release/v0.2 stateIdentity digest
// (`{"sha256": <StateDigest>}`) and reproduced by a verifier to authenticate the
// version-decision chain (ADR-036, §8.1).
func StateDigest(state map[string]any) (string, error) {
	canon, err := CanonicalizeState(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}
