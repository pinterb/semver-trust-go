// SPDX-License-Identifier: Apache-2.0

package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Lenient is a tag admitted by the plain-mode parser: either a §7.1-valid tag
// (Coerced false) or a Masterminds-style coercion of an out-of-grammar form
// (Coerced true). It exists only for the plain-mode display/list/latest/next
// surface (GO-041); nothing on a trust path consumes it.
type Lenient struct {
	// Version is the parsed value. For a coerced tag it is always a clean or
	// plain version — ParseLenient never coerces anything into a trust version.
	Version Version

	// Build holds SemVer build-metadata identifiers, retained for display
	// parity with the go-semver donor (Masterminds accepted them). Build
	// metadata is out of the §7.1 grammar, so it only ever appears with
	// Coerced true, and it never participates in precedence (SemVer §10).
	Build []string

	// Coerced reports that the raw tag was not §7.1-valid as written: a short
	// or v-less form back-filled to x.y.z, or a tag carrying build metadata.
	Coerced bool
}

// Canonical renders the donor-parity display form: the bare normalized SemVer
// (no "v"), with any component path kept as a prefix, the trust suffix
// rendered as its pre-release identifiers, and build metadata reattached.
// This mirrors what go-semver printed (Masterminds Version.String()).
func (l Lenient) Canonical() string {
	tag := l.Version.String() // [component/]vX.Y.Z[-pre]
	vAt := 0                  // the grammar "v" is the byte after the component path
	if i := strings.LastIndexByte(tag, '/'); i >= 0 {
		vAt = i + 1
	}
	var sb strings.Builder
	sb.WriteString(tag[:vAt])   // component path prefix, if any
	sb.WriteString(tag[vAt+1:]) // the version with its "v" dropped
	if len(l.Build) > 0 {
		sb.WriteByte('+')
		sb.WriteString(strings.Join(l.Build, "."))
	}
	return sb.String()
}

// ParseLenient parses a tag for the plain-mode surface, accepting what the
// go-semver donor accepted (Masterminds NewVersion): an optional "v" prefix,
// one to three numeric core fields with the missing ones back-filled to zero
// (2.1 → 2.1.0, v3 → 3.0.0), an optional pre-release, and optional build
// metadata (accepted for display parity; §7.1 rejects it, so such a tag is
// Coerced and can never be a trust version).
//
// The §7.1 fail-closed contract scopes the leniency (maintainer decision
// 2026-07-07): a §7.1-valid tag parses strictly (Coerced false, trust
// versions included), and any OTHER tag whose pre-release starts trust-shaped
// (t followed by digits) is invalid — a malformed trust shape (v1.0.0-t10.1)
// or a trust suffix on an out-of-grammar form (1.0-t2.1, v1.0.0-t2.1+b) is
// never coerced into a plain version. This is the one deliberate divergence
// from the donor, which had no trust grammar and would have admitted those as
// ordinary pre-releases.
//
// Strict Parse is untouched: this is a separate entry point, not a mode.
func ParseLenient(tag string) (Lenient, error) {
	// §7.1-valid tags need no coercion; this is also the only door through
	// which a trust version can enter the lenient-valid set.
	if v, err := Parse(tag); err == nil {
		return Lenient{Version: v}, nil
	}

	// Component paths are §7.1 vocabulary; the donor grammar had no "/" and
	// Masterminds rejects it, so a non-strict pathed tag is not coercible.
	if strings.ContainsRune(tag, '/') {
		return Lenient{}, &ParseError{
			Tag:    tag,
			Reason: "component-path tags must be §7.1-valid; they are not coerced",
		}
	}

	body := strings.TrimPrefix(tag, "v")
	if body == "" {
		return Lenient{}, &ParseError{Tag: tag, Reason: "version is empty"}
	}

	var build []string
	if plus := strings.IndexByte(body, '+'); plus >= 0 {
		buildStr := body[plus+1:]
		body = body[:plus]
		if buildStr == "" {
			return Lenient{}, &ParseError{Tag: tag, Reason: "build metadata is empty"}
		}
		build = strings.Split(buildStr, ".")
		for _, id := range build {
			if err := validateBuildIdent(id); err != nil {
				return Lenient{}, wrapTag(tag, err)
			}
		}
	}

	var pre []string
	if dash := strings.IndexByte(body, '-'); dash >= 0 {
		preStr := body[dash+1:]
		body = body[:dash]
		if preStr == "" {
			return Lenient{}, &ParseError{Tag: tag, Reason: "pre-release is empty"}
		}
		pre = strings.Split(preStr, ".")
		for _, id := range pre {
			if err := validatePrereleaseIdent(id); err != nil {
				return Lenient{}, wrapTag(tag, err)
			}
		}
	}

	// Fail closed on trust shapes: the tag did not strict-parse, so a
	// trust-shaped first identifier means either a malformed suffix or a trust
	// suffix on an out-of-grammar form. Neither may become a plain version.
	if len(pre) > 0 && isTrustShaped(pre[0]) {
		return Lenient{}, &ParseError{
			Tag:    tag,
			Reason: fmt.Sprintf("trust-shaped pre-release %q on a tag that is not §7.1-valid; trust shapes fail closed and are never coerced", pre[0]),
		}
	}

	fields := strings.Split(body, ".")
	if len(fields) > 3 {
		return Lenient{}, &ParseError{
			Tag:    tag,
			Reason: fmt.Sprintf("core-version has %d fields; at most MAJOR.MINOR.PATCH", len(fields)),
		}
	}
	core := [3]uint64{}
	names := [3]string{"major", "minor", "patch"}
	for i, f := range fields {
		// Missing fields back-fill to zero below; present ones must be numeric.
		// Leading zeros coerce away (01.2 → 1.2.0), matching Masterminds.
		n, err := parseLenientNumericField(f, names[i])
		if err != nil {
			return Lenient{}, wrapTag(tag, err)
		}
		core[i] = n
	}

	return Lenient{
		Version: Version{Major: core[0], Minor: core[1], Patch: core[2], Pre: pre},
		Build:   build,
		Coerced: true,
	}, nil
}

// parseLenientNumericField parses one coercible core field: decimal digits,
// leading zeros tolerated (Masterminds NewVersion's `[0-9]+`), so 4.x stays
// invalid while 01.2.3 normalizes.
func parseLenientNumericField(s, name string) (uint64, error) {
	if s == "" {
		return 0, &ParseError{Reason: fmt.Sprintf("%s version is empty", name)}
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, &ParseError{Reason: fmt.Sprintf("%s version %q is not numeric", name, s)}
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, &ParseError{Reason: fmt.Sprintf("%s version %q is out of range", name, s)}
	}
	return n, nil
}

// validateBuildIdent checks one build-metadata identifier: non-empty and drawn
// from [0-9A-Za-z-] (SemVer 2.0.0 §10; leading zeros are fine there).
func validateBuildIdent(id string) error {
	if id == "" {
		return &ParseError{Reason: "build-metadata identifier is empty"}
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
		default:
			return &ParseError{Reason: fmt.Sprintf("build-metadata identifier %q has an invalid character %q", id, string(c))}
		}
	}
	return nil
}
