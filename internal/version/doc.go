// SPDX-License-Identifier: Apache-2.0

// Package version implements the SemVer-Trust canonical version type: the
// value parsed from and rendered to a git tag under the spec §7.1 tag grammar.
//
// A tag is [component-path "/"] "v" ( core-version / trust-version ), where a
// core-version is MAJOR.MINOR.PATCH and a trust-version appends a trust suffix
// "-t<level>.<iteration>" (level a single digit 0-3, iteration a SemVer numeric
// identifier that starts at 1). Parse classifies a tag into exactly one of
// three outcomes, matching the conformance grammar vectors:
//
//   - trust_version — conforms to §7.1 (a clean core-version or a trust suffix).
//   - plain_version — valid SemVer 2.0.0 whose pre-release is not trust-shaped
//     (for example v1.4.0-rc.1); the degrade-gracefully case.
//   - invalid — everything else. Trust-shaped-but-malformed suffixes such as
//     t10.1, t1, and t1.0 fail *closed* here; they never fall through to
//     plain_version.
//
// The parser is strict (spec §6 hybrid-parser decision): it performs no
// Masterminds-style coercion of short or v-less forms, and it rejects SemVer
// build metadata, which the §7.1 grammar does not admit and which Go modules
// reject (§7.4). Lenient plain-mode coercion is the separate ParseLenient
// entry point (GO-041), scoped to the display/list/latest/next surface: it
// never feeds trust operations, and it never coerces a trust shape — a tag
// whose pre-release is trust-shaped is either §7.1-valid or invalid.
//
// Precedence follows SemVer 2.0.0 §11 (Compare, Sort); the trust suffix
// participates as ordinary pre-release identifiers, so the "t10 < t2" and
// numeric-iteration hazards resolve by the standard rules. Component paths
// partition the ordering: comparing across different components is a caller
// error.
package version
