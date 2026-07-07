// SPDX-License-Identifier: Apache-2.0

package version

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseError explains why a tag failed the §7.1 grammar. Reason is a
// human-readable message intended for diagnostics and the invalid-outcome
// vectors; it is not part of the API contract, so callers must not match on its
// text. Test against the fact of the error, not its wording.
type ParseError struct {
	// Tag is the input that failed to parse.
	Tag string
	// Reason is a human-readable explanation, citing the spec section.
	Reason string
}

// Error implements error.
func (e *ParseError) Error() string {
	if e.Tag == "" {
		return e.Reason
	}
	return fmt.Sprintf("%q: %s", e.Tag, e.Reason)
}

// Parse classifies a tag under the SemVer-Trust §7.1 grammar. It returns a
// Version for the trust_version and plain_version outcomes and a *ParseError
// for the invalid outcome.
//
// The grammar contract is three-outcome and fails closed. A pre-release whose
// first identifier is trust-shaped (the letter t followed by one or more
// digits) MUST be a well-formed trust suffix — exactly t<level>.<iteration>
// with level a single digit 0-3 and iteration a numeric identifier that starts
// at 1 — or the whole tag is invalid. Such malformed suffixes (t10.1, t1, t1.0,
// t4.1) never degrade to plain_version. A non-trust-shaped pre-release
// (rc.1, alpha, …) yields plain_version.
//
// Parsing is strict: no coercion of short (1, 1.2) or v-less forms, and build
// metadata is rejected (§7.1 admits none; §7.4 notes Go modules reject it).
func Parse(tag string) (Version, error) {
	if tag == "" {
		return Version{}, &ParseError{Tag: tag, Reason: "empty tag"}
	}

	component := ""
	rest := tag
	if i := strings.LastIndexByte(tag, '/'); i >= 0 {
		component = tag[:i]
		rest = tag[i+1:]
		if err := validateComponentPath(tag, component); err != nil {
			return Version{}, err
		}
	}

	if !strings.HasPrefix(rest, "v") {
		return Version{}, &ParseError{
			Tag:    tag,
			Reason: `tag must carry "v" before the core-version (§7.1)`,
		}
	}

	major, minor, patch, pre, err := parseSemverCore(rest[1:])
	if err != nil {
		return Version{}, wrapTag(tag, err)
	}

	v := Version{Component: component, Major: major, Minor: minor, Patch: patch}

	// Clean core-version: a valid §7.1 trust_version with no suffix.
	if len(pre) == 0 {
		return v, nil
	}

	// Trust-shaped pre-releases must validate strictly or fail closed.
	if isTrustShaped(pre[0]) {
		trust, terr := classifyTrustSuffix(pre)
		if terr != nil {
			return Version{}, wrapTag(tag, terr)
		}
		v.Trust = trust
		return v, nil
	}

	// Non-trust pre-release: the degrade-gracefully plain_version outcome.
	v.Pre = pre
	return v, nil
}

// parseSemver parses a bare SemVer 2.0.0 version (an optional leading "v", then
// MAJOR.MINOR.PATCH and an optional pre-release) into a Version, performing no
// trust-shape recognition — every pre-release, including trust-shaped ones,
// lands in Pre. It backs the precedence comparator's conformance harness, whose
// vectors are bare versions and include forms (t10.1) that the §7.1 tag grammar
// rejects but that must still compare as raw SemVer.
func parseSemver(s string) (Version, error) {
	body := strings.TrimPrefix(s, "v")
	major, minor, patch, pre, err := parseSemverCore(body)
	if err != nil {
		return Version{}, err
	}
	return Version{Major: major, Minor: minor, Patch: patch, Pre: pre}, nil
}

// parseSemverCore parses the SemVer body after any "v": the numeric core and
// the pre-release identifiers. It is strict — three numeric fields with no
// leading zeros and valid pre-release identifiers — and rejects build metadata.
func parseSemverCore(s string) (major, minor, patch uint64, pre []string, err error) {
	if s == "" {
		return 0, 0, 0, nil, &ParseError{Reason: "version is empty"}
	}
	if strings.IndexByte(s, '+') >= 0 {
		return 0, 0, 0, nil, &ParseError{
			Reason: "build metadata is not permitted in a trust-version tag (§7.1)",
		}
	}

	core := s
	if dash := strings.IndexByte(s, '-'); dash >= 0 {
		core = s[:dash]
		preStr := s[dash+1:]
		if preStr == "" {
			return 0, 0, 0, nil, &ParseError{Reason: "pre-release is empty"}
		}
		pre = strings.Split(preStr, ".")
		for _, id := range pre {
			if verr := validatePrereleaseIdent(id); verr != nil {
				return 0, 0, 0, nil, verr
			}
		}
	}

	fields := strings.Split(core, ".")
	if len(fields) != 3 {
		return 0, 0, 0, nil, &ParseError{
			Reason: fmt.Sprintf("core-version must be MAJOR.MINOR.PATCH; %q is not (§7.1)", core),
		}
	}
	if major, err = parseNumericField(fields[0], "major"); err != nil {
		return 0, 0, 0, nil, err
	}
	if minor, err = parseNumericField(fields[1], "minor"); err != nil {
		return 0, 0, 0, nil, err
	}
	if patch, err = parseNumericField(fields[2], "patch"); err != nil {
		return 0, 0, 0, nil, err
	}
	return major, minor, patch, pre, nil
}

// classifyTrustSuffix validates a trust-shaped pre-release (its first identifier
// already satisfied isTrustShaped) into a TrustSuffix, failing closed with a
// specific reason on any malformation. The check order yields the exact reasons
// the invalid-grammar vectors expect.
func classifyTrustSuffix(pre []string) (*TrustSuffix, error) {
	if len(pre) == 1 {
		return nil, &ParseError{
			Reason: `trust-suffix requires ".<iteration>"; iteration is absent (§7.1)`,
		}
	}
	if len(pre) > 2 {
		return nil, &ParseError{
			Reason: "trust-suffix must be exactly t<level>.<iteration> (§7.1)",
		}
	}

	digits := pre[0][1:] // drop the leading "t"; isTrustShaped guaranteed >=1 digit
	if len(digits) != 1 {
		return nil, &ParseError{
			Reason: fmt.Sprintf("level must be a single digit 0-3; %q has %d digits (§7.1)", pre[0], len(digits)),
		}
	}
	level := digits[0] - '0'
	if level > 3 {
		return nil, &ParseError{
			Reason: "level out of range; only 0-3 are defined (§7.1)",
		}
	}

	iterStr := pre[1]
	if iterStr == "0" {
		return nil, &ParseError{
			Reason: `iteration starts at 1; "0" is not allowed (§7.1)`,
		}
	}
	iteration, err := parseIteration(iterStr)
	if err != nil {
		return nil, err
	}
	return &TrustSuffix{Level: level, Iteration: iteration}, nil
}

// isTrustShaped reports whether id is the letter t followed by one or more
// decimal digits — the discriminator that puts a pre-release into the
// fail-closed trust bucket rather than the plain bucket.
func isTrustShaped(id string) bool {
	if len(id) < 2 || id[0] != 't' {
		return false
	}
	for i := 1; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return true
}

// parseIteration parses a trust iteration: a numeric identifier >= 1 with no
// leading zero. The caller handles the "0" case for its specific message.
func parseIteration(s string) (uint64, error) {
	if len(s) > 1 && s[0] == '0' {
		return 0, &ParseError{Reason: fmt.Sprintf("iteration %q must not have a leading zero (§7.1)", s)}
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, &ParseError{Reason: fmt.Sprintf("iteration %q must be numeric (§7.1)", s)}
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, &ParseError{Reason: fmt.Sprintf("iteration %q is out of range", s)}
	}
	return n, nil
}

// parseNumericField parses one MAJOR/MINOR/PATCH field: decimal digits with no
// leading zero (SemVer 2.0.0).
func parseNumericField(s, name string) (uint64, error) {
	if s == "" {
		return 0, &ParseError{Reason: fmt.Sprintf("%s version is empty", name)}
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, &ParseError{Reason: fmt.Sprintf("%s version %q is not numeric (§7.1)", name, s)}
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, &ParseError{Reason: fmt.Sprintf("%s version %q must not have a leading zero (§7.1)", name, s)}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, &ParseError{Reason: fmt.Sprintf("%s version %q is out of range", name, s)}
	}
	return n, nil
}

// validatePrereleaseIdent checks one SemVer pre-release identifier: non-empty,
// drawn from [0-9A-Za-z-], and, when purely numeric, free of a leading zero.
func validatePrereleaseIdent(id string) error {
	if id == "" {
		return &ParseError{Reason: "pre-release identifier is empty"}
	}
	numeric := true
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
			numeric = false
		default:
			return &ParseError{Reason: fmt.Sprintf("pre-release identifier %q has an invalid character %q", id, string(c))}
		}
	}
	if numeric && len(id) > 1 && id[0] == '0' {
		return &ParseError{Reason: fmt.Sprintf("numeric pre-release identifier %q must not have a leading zero", id)}
	}
	return nil
}

// validateComponentPath checks a component-path prefix: non-empty, "/"-separated
// segments each drawn from the tag ruleset's [0-9A-Za-z._-] alphabet.
func validateComponentPath(tag, p string) error {
	if p == "" {
		return &ParseError{Tag: tag, Reason: "component path is empty"}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" {
			return &ParseError{Tag: tag, Reason: fmt.Sprintf("component path %q has an empty segment", p)}
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			switch {
			case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			case c == '.', c == '_', c == '-':
			default:
				return &ParseError{Tag: tag, Reason: fmt.Sprintf("component path %q has an invalid character %q", p, string(c))}
			}
		}
	}
	return nil
}

// wrapTag attaches the failing tag to a *ParseError that was raised without it.
func wrapTag(tag string, err error) error {
	if pe, ok := err.(*ParseError); ok && pe.Tag == "" {
		pe.Tag = tag
		return pe
	}
	return err
}
