// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/semver-trust/semver-trust-go/internal/trust"
)

// MetaPolicy is the transition-facing view of a policy state (§5.4, ADR-028):
// its pinned path/digest, meta-paths and required level, the trust-material map
// (path → digest) and role→path map, the authorized commit signers, and an
// optional adoption boundary.
type MetaPolicy struct {
	Path              string
	Digest            string
	RequiredLevel     string
	MetaPaths         []string
	TrustMaterial     map[string]string
	TrustRoles        map[string]string
	AuthorizedSigners []string
	AdoptionBoundary  *string
}

// BootstrapDescriptor is the out-of-band chain-genesis authority (ADR-028): it
// pins the subject, range mode and boundary, the active policy path/digest,
// trust material and roles, the mandatory attestation-workflow meta-paths, and
// the verification/clock profiles.
type BootstrapDescriptor struct {
	Authenticated       bool
	Repository          string
	Component           string
	RangeMode           string
	Boundary            *string
	VerificationProfile string
	ClockProfile        string
	PolicyPath          string
	PolicyDigest        string
	TrustMaterial       map[string]string
	TrustRoles          map[string]string
	MandatoryMetaPaths  []string
}

// PredecessorPolicy is the accepted predecessor chain head that governs a
// recurring transition (ADR-028): the active facts it binds for the interval.
type PredecessorPolicy struct {
	Accepted            bool
	ChainHead           bool
	Repository          string
	Component           string
	VerificationProfile string
	ClockProfile        string
	PolicyPath          string
	PolicyDigest        string
	TrustMaterial       map[string]string
	TrustRoles          map[string]string
	MandatoryMetaPaths  []string
}

// TransitionCommit is a commit in the interval as the transition sees it: its
// signer, level, and diff paths.
type TransitionCommit struct {
	Signer string
	Level  string
	Paths  []string
}

// TransitionInputs are the release-time facts a policy transition is evaluated
// against (§5.4, ADR-028).
type TransitionInputs struct {
	Repository            string
	Component             string
	Authority             string // bootstrap | predecessor
	RangeMode             string
	Boundary              *string
	VerificationProfile   string
	ClockProfile          string
	VerificationTime      string
	ProvidedTrustMaterial map[string]string
	Commits               []TransitionCommit
}

// SelectPolicyTransition evaluates a policy transition (§5.4, ADR-028): the
// active policy and its authority (an authenticated bootstrap descriptor at
// genesis, or the accepted predecessor chain head for recurrence) govern the
// interval; the candidate policy at TO is only activated for the next interval,
// and may never lower its own guardrails or authorize its own enrollment.
//
// It returns the evaluated policy digest, the activated (candidate) digest on
// success (empty on failure), and a stable reason (empty when the transition
// verifies). A faithful port of the conformance oracle's _policy_transition;
// the production verifier feeds it real policy state (tracked in
// semver-trust-go#76).
func SelectPolicyTransition(active, candidate MetaPolicy, authority string, bootstrap *BootstrapDescriptor, predecessor *PredecessorPolicy, in TransitionInputs) (evaluated, activated, reason string) {
	fail := func(r string) (string, string, string) { return active.Digest, "", r }

	if !trustRolesValid(active.TrustMaterial, active.TrustRoles) {
		return fail("active_trust_roles_invalid")
	}
	if !trustRolesValid(candidate.TrustMaterial, candidate.TrustRoles) {
		return fail("candidate_trust_roles_invalid")
	}

	var mandatoryMetaPaths []string
	switch authority {
	case "bootstrap":
		b := bootstrap
		if b == nil {
			return fail("bootstrap_missing")
		}
		if !b.Authenticated {
			return fail("bootstrap_unauthenticated")
		}
		if b.Repository != in.Repository || b.Component != in.Component {
			return fail("bootstrap_subject_mismatch")
		}
		if b.RangeMode != in.RangeMode {
			return fail("bootstrap_range_mode_mismatch")
		}
		if !strEq(b.Boundary, in.Boundary) {
			return fail("bootstrap_boundary_mismatch")
		}
		if b.VerificationProfile != in.VerificationProfile {
			return fail("bootstrap_profile_mismatch")
		}
		if b.ClockProfile != in.ClockProfile {
			return fail("bootstrap_clock_profile_mismatch")
		}
		if b.PolicyPath != active.Path || b.PolicyDigest != active.Digest {
			return fail("bootstrap_policy_mismatch")
		}
		if !reflect.DeepEqual(b.TrustMaterial, active.TrustMaterial) {
			return fail("bootstrap_trust_material_mismatch")
		}
		if !reflect.DeepEqual(b.TrustRoles, active.TrustRoles) {
			return fail("bootstrap_trust_roles_mismatch")
		}
		if candidate.Path != active.Path || candidate.Digest != active.Digest ||
			!reflect.DeepEqual(candidate.TrustMaterial, active.TrustMaterial) ||
			!reflect.DeepEqual(candidate.TrustRoles, active.TrustRoles) {
			return fail("bootstrap_candidate_mismatch")
		}
		mandatoryMetaPaths = b.MandatoryMetaPaths

	case "predecessor":
		p := predecessor
		if p == nil {
			return fail("predecessor_missing")
		}
		if !p.Accepted {
			return fail("predecessor_not_accepted")
		}
		if !p.ChainHead {
			return fail("predecessor_not_chain_head")
		}
		if p.Repository != in.Repository || p.Component != in.Component {
			return fail("predecessor_subject_mismatch")
		}
		if p.VerificationProfile != in.VerificationProfile {
			return fail("predecessor_profile_mismatch")
		}
		if p.ClockProfile != in.ClockProfile {
			return fail("predecessor_clock_profile_mismatch")
		}
		if p.PolicyPath != active.Path || p.PolicyDigest != active.Digest ||
			!reflect.DeepEqual(p.TrustMaterial, active.TrustMaterial) {
			return fail("predecessor_policy_mismatch")
		}
		if !reflect.DeepEqual(p.TrustRoles, active.TrustRoles) {
			return fail("predecessor_trust_roles_mismatch")
		}
		mandatoryMetaPaths = p.MandatoryMetaPaths

	default:
		return fail("unknown_policy_authority")
	}

	if !verificationTimeValid(in.VerificationTime) {
		return fail("verification_time_missing_or_invalid")
	}
	for _, path := range mandatoryMetaPaths {
		if !metaCovers(active, path) {
			return fail("active_authority_meta_uncovered")
		}
	}
	for _, path := range mandatoryMetaPaths {
		if !metaCovers(candidate, path) {
			return fail("candidate_authority_meta_uncovered")
		}
	}
	if !mandatoryMetaCovered(active) {
		return fail("active_mandatory_meta_uncovered")
	}
	if !reflect.DeepEqual(in.ProvidedTrustMaterial, active.TrustMaterial) {
		return fail("trust_material_mismatch")
	}
	if candidate.Path != active.Path {
		return fail("candidate_policy_path_changed")
	}
	if levelRank(candidate.RequiredLevel) < levelRank(active.RequiredLevel) {
		return fail("candidate_meta_level_lowered")
	}
	if candidate.AdoptionBoundary != nil && !strEq(candidate.AdoptionBoundary, in.Boundary) {
		return fail("adoption_boundary_changed")
	}
	if !mandatoryMetaCovered(candidate) {
		return fail("candidate_mandatory_meta_uncovered")
	}

	activeSigners := make(map[string]bool, len(active.AuthorizedSigners))
	for _, s := range active.AuthorizedSigners {
		activeSigners[s] = true
	}
	for _, c := range in.Commits {
		if !activeSigners[c.Signer] {
			return fail("unknown_active_signer")
		}
	}

	var patterns []string
	patterns = append(patterns, active.MetaPaths...)
	patterns = append(patterns, candidate.MetaPaths...)
	patterns = append(patterns, mandatoryMetaPaths...)
	patterns = append(patterns, active.Path, candidate.Path)
	for path := range active.TrustMaterial {
		patterns = append(patterns, path)
	}
	for path := range candidate.TrustMaterial {
		patterns = append(patterns, path)
	}
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = globToRegexp(p)
	}
	required := levelRank(active.RequiredLevel)
	for _, c := range in.Commits {
		touchesMeta := false
		for _, path := range c.Paths {
			for _, rx := range compiled {
				if rx.MatchString(path) {
					touchesMeta = true
					break
				}
			}
			if touchesMeta {
				break
			}
		}
		if touchesMeta && levelRank(c.Level) < required {
			return fail("under_level_meta_commit")
		}
	}

	return active.Digest, candidate.Digest, ""
}

func trustRolesValid(material, roles map[string]string) bool {
	if len(roles) == 0 {
		return false
	}
	roleValues := make(map[string]bool, len(roles))
	for _, path := range roles {
		roleValues[path] = true
	}
	materialKeys := make(map[string]bool, len(material))
	for path := range material {
		materialKeys[path] = true
	}
	return reflect.DeepEqual(roleValues, materialKeys)
}

func metaCovers(policy MetaPolicy, path string) bool {
	for _, pattern := range policy.MetaPaths {
		if globToRegexp(pattern).MatchString(path) {
			return true
		}
	}
	return false
}

func mandatoryMetaCovered(policy MetaPolicy) bool {
	if !metaCovers(policy, policy.Path) {
		return false
	}
	for path := range policy.TrustMaterial {
		if !metaCovers(policy, path) {
			return false
		}
	}
	return true
}

func verificationTimeValid(s string) bool {
	if !strings.HasSuffix(s, "Z") {
		return false
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

func levelRank(s string) int {
	l, err := trust.ParseLevel(s)
	if err != nil {
		return -1
	}
	return int(l)
}

func strEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// globToRegexp compiles a §5.1-style meta-path glob (segment-aware: '*' within
// a segment, '**' across segments) — the same shape trust scope globs use,
// ported from the oracle's _glob_to_re.
func globToRegexp(pattern string) *regexp.Regexp {
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
	return regexp.MustCompile(sb.String())
}
