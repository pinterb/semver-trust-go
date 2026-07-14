// SPDX-License-Identifier: Apache-2.0

package policy

import "testing"

// material and roles helpers return fresh maps so a mutating case never leaks
// into another.
func ptMaterial() map[string]string {
	return map[string]string{"m/humans": "d1", "m/attesters": "d2"}
}
func ptRoles() map[string]string {
	return map[string]string{"human_signers": "m/humans", "attesters": "m/attesters"}
}
func ptPolicyState() MetaPolicy {
	return MetaPolicy{
		Path: ".semver-trust/policy.toml", Digest: "sha256:pa", RequiredLevel: "T2",
		MetaPaths: []string{"**"}, TrustMaterial: ptMaterial(), TrustRoles: ptRoles(),
		AuthorizedSigners: []string{"alice"}, AdoptionBoundary: nil,
	}
}
func ptBaseInputs(authority string) TransitionInputs {
	return TransitionInputs{
		Repository: "repo", Component: "app", Authority: authority,
		RangeMode: "inception", Boundary: nil, VerificationProfile: "vp", ClockProfile: "cp",
		VerificationTime: "2026-01-01T00:00:00Z", ProvidedTrustMaterial: ptMaterial(),
		Commits: []TransitionCommit{{Signer: "alice", Level: "T2", Paths: []string{".semver-trust/policy.toml"}}},
	}
}
func ptValidBootstrap() *BootstrapDescriptor {
	return &BootstrapDescriptor{
		Authenticated: true, Repository: "repo", Component: "app", RangeMode: "inception", Boundary: nil,
		VerificationProfile: "vp", ClockProfile: "cp", PolicyPath: ".semver-trust/policy.toml", PolicyDigest: "sha256:pa",
		TrustMaterial: ptMaterial(), TrustRoles: ptRoles(), MandatoryMetaPaths: nil,
	}
}
func ptValidPredecessor() *PredecessorPolicy {
	return &PredecessorPolicy{
		Accepted: true, ChainHead: true, Repository: "repo", Component: "app",
		VerificationProfile: "vp", ClockProfile: "cp", PolicyPath: ".semver-trust/policy.toml", PolicyDigest: "sha256:pa",
		TrustMaterial: ptMaterial(), TrustRoles: ptRoles(), MandatoryMetaPaths: nil,
	}
}

// TestSelectPolicyTransitionOracleSurface exercises the ADR-028 reasons the
// vendored policy-transition vectors do not cover (16 of 33), so the
// implementation mirrors the oracle's full decision surface.
func TestSelectPolicyTransitionOracleSurface(t *testing.T) {
	// Base sanity: a valid bootstrap transition and a valid predecessor
	// transition both verify.
	if _, act, reason := SelectPolicyTransition(ptPolicyState(), ptPolicyState(), ptValidBootstrap(), nil, ptBaseInputs("bootstrap")); reason != "" || act != "sha256:pa" {
		t.Fatalf("valid bootstrap = %q/%q, want activated sha256:pa/none", act, reason)
	}
	if _, act, reason := SelectPolicyTransition(ptPolicyState(), ptPolicyState(), nil, ptValidPredecessor(), ptBaseInputs("predecessor")); reason != "" || act != "sha256:pa" {
		t.Fatalf("valid predecessor = %q/%q, want activated sha256:pa/none", act, reason)
	}

	type tc struct {
		name string
		run  func() string // returns the reason
		want string
	}
	bootstrap := func(mut func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs)) func() string {
		return func() string {
			a, c, b, in := ptPolicyState(), ptPolicyState(), ptValidBootstrap(), ptBaseInputs("bootstrap")
			mut(&a, &c, b, &in)
			_, _, r := SelectPolicyTransition(a, c, b, nil, in)
			return r
		}
	}
	predecessor := func(mut func(a, c *MetaPolicy, p *PredecessorPolicy, in *TransitionInputs)) func() string {
		return func() string {
			a, c, p, in := ptPolicyState(), ptPolicyState(), ptValidPredecessor(), ptBaseInputs("predecessor")
			mut(&a, &c, p, &in)
			_, _, r := SelectPolicyTransition(a, c, nil, p, in)
			return r
		}
	}

	cases := []tc{
		{"active roles do not cover material", bootstrap(func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs) {
			a.TrustRoles = map[string]string{"human_signers": "m/humans"} // missing attesters
		}), "active_trust_roles_invalid"},
		{"candidate roles empty", bootstrap(func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs) {
			c.TrustRoles = map[string]string{}
		}), "candidate_trust_roles_invalid"},
		{"unknown authority", bootstrap(func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs) {
			in.Authority = "sideways"
		}), "unknown_policy_authority"},
		{"bootstrap subject mismatch", bootstrap(func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs) {
			b.Repository = "other"
		}), "bootstrap_subject_mismatch"},
		{"bootstrap range-mode mismatch", bootstrap(func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs) {
			b.RangeMode = "adoption"
		}), "bootstrap_range_mode_mismatch"},
		{"bootstrap profile mismatch", bootstrap(func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs) {
			b.VerificationProfile = "vp2"
		}), "bootstrap_profile_mismatch"},
		{"bootstrap trust-material mismatch", bootstrap(func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs) {
			b.TrustMaterial = map[string]string{"m/humans": "d1", "m/attesters": "different"}
		}), "bootstrap_trust_material_mismatch"},
		{"candidate differs from active at genesis", bootstrap(func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs) {
			c.Digest = "sha256:pb"
		}), "bootstrap_candidate_mismatch"},
		{"mandatory meta path uncovered by active", bootstrap(func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs) {
			a.MetaPaths = []string{"services/**"}
			c.MetaPaths = []string{"services/**"}
			b.MandatoryMetaPaths = []string{"ci/release"}
		}), "active_authority_meta_uncovered"},
		{"active meta does not cover its own policy path", bootstrap(func(a, c *MetaPolicy, b *BootstrapDescriptor, in *TransitionInputs) {
			a.MetaPaths = []string{"services/**"}
			c.MetaPaths = []string{"services/**"}
		}), "active_mandatory_meta_uncovered"},
		{"predecessor not accepted", predecessor(func(a, c *MetaPolicy, p *PredecessorPolicy, in *TransitionInputs) {
			p.Accepted = false
		}), "predecessor_not_accepted"},
		{"predecessor subject mismatch", predecessor(func(a, c *MetaPolicy, p *PredecessorPolicy, in *TransitionInputs) {
			p.Component = "other"
		}), "predecessor_subject_mismatch"},
		{"predecessor profile mismatch", predecessor(func(a, c *MetaPolicy, p *PredecessorPolicy, in *TransitionInputs) {
			p.VerificationProfile = "vp2"
		}), "predecessor_profile_mismatch"},
		{"predecessor clock-profile mismatch", predecessor(func(a, c *MetaPolicy, p *PredecessorPolicy, in *TransitionInputs) {
			p.ClockProfile = "cp2"
		}), "predecessor_clock_profile_mismatch"},
		{"predecessor trust-roles mismatch", predecessor(func(a, c *MetaPolicy, p *PredecessorPolicy, in *TransitionInputs) {
			p.TrustRoles = map[string]string{"human_signers": "m/humans", "attesters": "m/attesters", "extra": "m/humans"}
		}), "predecessor_trust_roles_mismatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.run(); got != c.want {
				t.Errorf("reason = %q, want %q", got, c.want)
			}
		})
	}

	// predecessor_missing: predecessor authority with a nil descriptor.
	t.Run("predecessor missing", func(t *testing.T) {
		_, _, r := SelectPolicyTransition(ptPolicyState(), ptPolicyState(), nil, nil, ptBaseInputs("predecessor"))
		if r != "predecessor_missing" {
			t.Errorf("reason = %q, want predecessor_missing", r)
		}
	})
}
