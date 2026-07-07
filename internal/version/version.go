// SPDX-License-Identifier: Apache-2.0

package version

import (
	"strconv"
	"strings"
)

// Kind is the outcome class of a parsed tag under the §7.1 grammar. The invalid
// outcome is reported as a parse error, never as a Kind, so a Version always
// carries one of the two values below.
type Kind uint8

const (
	// KindTrust is a version that conforms to the §7.1 canonical grammar: a
	// clean core-version or a "-t<level>.<iteration>" trust suffix.
	KindTrust Kind = iota
	// KindPlain is a valid SemVer 2.0.0 version whose pre-release is not
	// trust-shaped (the degrade-gracefully case, e.g. v1.4.0-rc.1).
	KindPlain
)

// String returns the vector-facing name of the kind ("trust_version" or
// "plain_version").
func (k Kind) String() string {
	switch k {
	case KindTrust:
		return "trust_version"
	case KindPlain:
		return "plain_version"
	default:
		return "unknown"
	}
}

// TrustSuffix is the "-t<level>.<iteration>" tail of a trust-version (§7.1).
// Level is a single digit 0-3; Iteration is a SemVer numeric identifier that
// starts at 1.
type TrustSuffix struct {
	Level     uint8
	Iteration uint64
}

// Version is a parsed SemVer-Trust tag. It is treated as immutable after Parse;
// the trust-aware and increment helpers return fresh values rather than
// mutating in place.
//
// Exactly one shape holds at a time: a clean version has Trust == nil and
// Pre == nil; a trust version has Trust != nil and Pre == nil; a plain version
// has Trust == nil and len(Pre) > 0. Build metadata is not represented because
// the parser rejects it (§7.1/§7.4).
type Version struct {
	// Component is the component-path tag prefix (e.g. "auth", "pkg/common");
	// empty when the tag has no path.
	Component string

	Major uint64
	Minor uint64
	Patch uint64

	// Trust is the trust suffix, or nil for a clean or plain version.
	Trust *TrustSuffix

	// Pre holds the dot-separated pre-release identifiers of a plain version,
	// or nil for a clean or trust version.
	Pre []string
}

// Kind reports whether v conforms to the §7.1 grammar (KindTrust, covering both
// clean and trust-suffixed versions) or is a plain SemVer pre-release version
// (KindPlain).
func (v Version) Kind() Kind {
	if len(v.Pre) > 0 {
		return KindPlain
	}
	return KindTrust
}

// String renders v as its canonical tag, the inverse of Parse: Parse(v.String())
// equals v for every value Parse produces.
func (v Version) String() string {
	var sb strings.Builder
	if v.Component != "" {
		sb.WriteString(v.Component)
		sb.WriteByte('/')
	}
	sb.WriteByte('v')
	sb.WriteString(strconv.FormatUint(v.Major, 10))
	sb.WriteByte('.')
	sb.WriteString(strconv.FormatUint(v.Minor, 10))
	sb.WriteByte('.')
	sb.WriteString(strconv.FormatUint(v.Patch, 10))

	switch {
	case v.Trust != nil:
		sb.WriteString("-t")
		sb.WriteString(strconv.FormatUint(uint64(v.Trust.Level), 10))
		sb.WriteByte('.')
		sb.WriteString(strconv.FormatUint(v.Trust.Iteration, 10))
	case len(v.Pre) > 0:
		sb.WriteByte('-')
		sb.WriteString(strings.Join(v.Pre, "."))
	}
	return sb.String()
}
