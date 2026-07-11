// SPDX-License-Identifier: Apache-2.0

// Package vcs is the plain-mode base layer over a git repository's tags: the
// degrade-gracefully surface that works with no policy file, no attestations,
// and no trust configuration at all (GO-021; implementation-plan §5 "plain
// mode works with zero trust config").
//
// It offers three operations, layered from the raw repository upward:
//
//   - Tags enumerates every tag ref — lightweight and annotated alike — in the
//     repository's own ref-iteration order. It is raw enumeration: no parsing,
//     no filtering, no SemVer sort.
//   - ParseTags, Latest, and Next add the version glue: strict §7.1 parsing of
//     the raw tags (via internal/version), SemVer-precedence sort, and a
//     node-semver "next" bump with the donor's 0.0.0 bootstrap for a tagless
//     repository. Tags that fail the strict parse are dropped, but their count
//     is always surfaced — plain-mode lenient filtering is allowed, silent
//     dropping is not (go-semver audit §5.2).
//   - CreateTag writes an annotated tag with an injected tagger identity and
//     timestamp (ADR-018: verification-shaped code takes an injected clock and
//     never calls time.Now).
//
// The tag-enumeration surface (Tags, rootPath) is ported from go-semver's
// internal/git package, replacing its abandoned gopkg.in/src-d/go-git.v4
// dependency with the maintained github.com/go-git/go-git/v5. The latest/next
// glue and annotated-tag creation are net-new.
//
// Component paths: the ported surface follows the donor, which had no component
// concept — bare, component-less tags (the empty component path) are the
// modeled case. ParseTags accepts whatever internal/version parses, and Latest
// and Next delegate cross-component ordering to internal/version, which reports
// a mix of component paths as an error rather than guessing. Component-scoped
// listing and re-cut arrive with later phases.
//
// Lenient Masterminds-style coercion of short (2.1) or v-less forms is out of
// scope here and lands in the plain-mode CLI (GO-041); this layer parses
// strictly, matching internal/version.
package vcs
