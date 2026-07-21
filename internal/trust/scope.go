// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// DefaultScope is the implicit scope for paths matching no scope glob (§5.1).
const DefaultScope = "default"

// Commit is the aggregation-facing view of a verified commit: its assigned
// level (§3.2, via Classify) and its diff paths. Every path a commit touches
// contributes the commit's own level: derivation claims are non-authoritative
// and never re-level outputs (spec repository ADR-033). A commit that could
// not be verified end-to-end never becomes a Commit — verification aborts
// instead (unverifiable ≠ T0, §5.2).
type Commit struct {
	ID    string
	Level Level
	Paths []string
}

// compileGlobs compiles gitignore-style scope globs (§5.1, conformance
// README): '*' matches within a path segment, '**' across segments, '?' a
// single non-separator character. Matching is segment-aware on purpose —
// services/auth/** must not match services/authz/….
func compileGlobs(patterns []string) (map[string]*regexp.Regexp, error) {
	compiled := make(map[string]*regexp.Regexp, len(patterns))
	for _, p := range patterns {
		if _, ok := compiled[p]; ok {
			continue
		}
		rx, err := compileGlob(p)
		if err != nil {
			return nil, err
		}
		compiled[p] = rx
	}
	return compiled, nil
}

func compileGlob(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty path glob")
	}
	var sb strings.Builder
	sb.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch {
		case strings.HasPrefix(pattern[i:], "**"):
			sb.WriteString(".*")
			i++
		case pattern[i] == '*':
			sb.WriteString("[^/]*")
		case pattern[i] == '?':
			sb.WriteString("[^/]")
		default:
			sb.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	sb.WriteByte('$')
	return regexp.Compile(sb.String())
}

// scopeGlobs returns the compiled glob set for a scope map.
func scopeGlobs(scopes map[string]string) (map[string]*regexp.Regexp, error) {
	patterns := make([]string, 0, len(scopes))
	for glob := range scopes {
		patterns = append(patterns, glob)
	}
	return compileGlobs(patterns)
}

// scopesOf returns the scopes a path falls into: every scope whose glob
// matches, or DefaultScope when none do (§5.1).
func scopesOf(path string, scopes map[string]string, globs map[string]*regexp.Regexp) []string {
	var touched []string
	for glob, name := range scopes {
		if globs[glob].MatchString(path) {
			touched = append(touched, name)
		}
	}
	if touched == nil {
		return []string{DefaultScope}
	}
	return touched
}

// PartitionScopes partitions commits by scope (§5.1): a commit touches a
// scope if any path in its diff matches the scope's globs, and a commit
// touching several scopes appears under each. The returned lists preserve
// commit order. Scoping keys off diff paths — objective ground truth from
// git — never off declared intent.
func PartitionScopes(scopes map[string]string, commits []Commit) (map[string][]string, error) {
	globs, err := scopeGlobs(scopes)
	if err != nil {
		return nil, err
	}
	partition := map[string][]string{}
	for _, c := range commits {
		touched := map[string]bool{}
		for _, path := range c.Paths {
			for _, scope := range scopesOf(path, scopes, globs) {
				touched[scope] = true
			}
		}
		names := make([]string, 0, len(touched))
		for scope := range touched {
			names = append(names, scope)
		}
		sort.Strings(names)
		for _, scope := range names {
			partition[scope] = append(partition[scope], c.ID)
		}
	}
	return partition, nil
}

// ScopeFloors computes own trust per touched scope (§5.2): the minimum over
// the levels contributed by every path of every commit touching the scope.
// There is no de-minimis exception and no derivation exception — a one-line
// T0 commit floors its scope exactly like a thousand-line one, and generated
// outputs floor at their commit's own level (ADR-033).
func ScopeFloors(scopes map[string]string, commits []Commit) (map[string]Level, error) {
	globs, err := scopeGlobs(scopes)
	if err != nil {
		return nil, err
	}
	floors := map[string]Level{}
	for _, c := range commits {
		for _, path := range c.Paths {
			level := c.Level
			for _, scope := range scopesOf(path, scopes, globs) {
				if current, ok := floors[scope]; !ok || level < current {
					floors[scope] = level
				}
			}
		}
	}
	return floors, nil
}

// MetaPathViolations returns, in commit order, the commits touching a
// declared meta-path below the required level (§5.4). Any violation means
// the release range MUST fail verification outright — not demote, fail; the
// abort belongs to the verification pipeline (§10 step 1), which treats a
// non-empty result as fatal.
func MetaPathViolations(metaPaths []string, required Level, commits []Commit) ([]string, error) {
	globs, err := compileGlobs(metaPaths)
	if err != nil {
		return nil, err
	}
	var violations []string
	for _, c := range commits {
		if c.Level >= required {
			continue
		}
		for _, path := range c.Paths {
			if matchesAny(path, metaPaths, globs) {
				violations = append(violations, c.ID)
				break
			}
		}
	}
	return violations, nil
}

// MetaPathCovers reports whether any of the meta-path globs covers path, using
// the same glob compilation MetaPathViolations uses. It is the seam consumed by
// internal/preflight (doctor policy/meta-coverage), which checks that the trust
// material and CI paths are inside the meta-path set.
func MetaPathCovers(metaPaths []string, path string) (bool, error) {
	globs, err := compileGlobs(metaPaths)
	if err != nil {
		return false, err
	}
	return matchesAny(path, metaPaths, globs), nil
}

func matchesAny(path string, patterns []string, globs map[string]*regexp.Regexp) bool {
	for _, p := range patterns {
		if globs[p].MatchString(path) {
			return true
		}
	}
	return false
}
