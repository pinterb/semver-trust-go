// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConformancePolicyTransition drives the spec's policy-transition vectors
// (§5.4, ADR-028) through SelectPolicyTransition: a bootstrap descriptor or the
// accepted predecessor chain head governs the interval, the candidate policy at
// TO activates only for the next interval and may not lower its guardrails or
// self-enroll, and every mismatch aborts with a stable reason.
func TestConformancePolicyTransition(t *testing.T) {
	doc := loadPolicyTransitionVectors(t)
	seen := 0
	for _, vec := range doc.Vectors {
		if vec.Kind != "policy_transition" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			in := vec.Inputs
			active := doc.policy(t, in.ActivePolicy)
			candidate := doc.policy(t, in.CandidatePolicy)

			var bootstrap *BootstrapDescriptor
			if in.Bootstrap != nil {
				bootstrap = doc.bootstrap(t, *in.Bootstrap)
			}
			var predecessor *PredecessorPolicy
			if in.Predecessor != nil {
				predecessor = doc.predecessor(t, *in.Predecessor)
			}

			ti := TransitionInputs{
				Repository:            in.Repository,
				Component:             in.Component,
				Authority:             in.Authority,
				RangeMode:             in.RangeMode,
				Boundary:              in.Boundary,
				VerificationProfile:   in.VerificationProfile,
				ClockProfile:          in.ClockProfile,
				VerificationTime:      in.VerificationTime,
				ProvidedTrustMaterial: in.ProvidedTrustMaterial,
			}
			for _, c := range in.Commits {
				ti.Commits = append(ti.Commits, TransitionCommit{Signer: c.Signer, Level: c.Level, Paths: c.Paths})
			}

			evaluated, activated, reason := SelectPolicyTransition(active, candidate, bootstrap, predecessor, ti)
			outcome := "verified"
			if reason != "" {
				outcome = "verification_failed"
			}
			if outcome != vec.Expected.Outcome {
				t.Errorf("outcome = %s (reason %q), want %s (reason %q)", outcome, reason, vec.Expected.Outcome, vec.Expected.Reason)
			}
			if reason != vec.Expected.Reason {
				t.Errorf("reason = %q, want %q", reason, vec.Expected.Reason)
			}
			if evaluated != vec.Expected.EvaluatedPolicy {
				t.Errorf("evaluated_policy = %q, want %q", evaluated, vec.Expected.EvaluatedPolicy)
			}
			if activated != vec.Expected.ActivatedPolicy {
				t.Errorf("activated_policy = %q, want %q", activated, vec.Expected.ActivatedPolicy)
			}
		})
	}
	if seen == 0 {
		t.Fatal("no policy_transition vectors ran")
	}
}

type ptPolicy struct {
	Path              string            `json:"path"`
	Digest            string            `json:"digest"`
	RequiredLevel     string            `json:"required_level"`
	MetaPaths         []string          `json:"meta_paths"`
	TrustMaterial     map[string]string `json:"trust_material"`
	TrustRoles        map[string]string `json:"trust_roles"`
	AuthorizedSigners []string          `json:"authorized_signers"`
	AdoptionBoundary  *string           `json:"adoption_boundary"`
}

type ptBootstrap struct {
	Authenticated       bool              `json:"authenticated"`
	Repository          string            `json:"repository"`
	Component           string            `json:"component"`
	RangeMode           string            `json:"range_mode"`
	Boundary            *string           `json:"boundary"`
	VerificationProfile string            `json:"verification_profile"`
	ClockProfile        string            `json:"clock_profile"`
	PolicyPath          string            `json:"policy_path"`
	PolicyDigest        string            `json:"policy_digest"`
	TrustMaterial       map[string]string `json:"trust_material"`
	TrustRoles          map[string]string `json:"trust_roles"`
	MandatoryMetaPaths  []string          `json:"mandatory_meta_paths"`
}

type ptPredecessor struct {
	Accepted            bool              `json:"accepted"`
	ChainHead           bool              `json:"chain_head"`
	Repository          string            `json:"repository"`
	Component           string            `json:"component"`
	VerificationProfile string            `json:"verification_profile"`
	ClockProfile        string            `json:"clock_profile"`
	PolicyPath          string            `json:"policy_path"`
	PolicyDigest        string            `json:"policy_digest"`
	TrustMaterial       map[string]string `json:"trust_material"`
	TrustRoles          map[string]string `json:"trust_roles"`
	MandatoryMetaPaths  []string          `json:"mandatory_meta_paths"`
}

type ptVectorFile struct {
	SpecVersion  string                   `json:"spec_version"`
	Policies     map[string]ptPolicy      `json:"policies"`
	Bootstraps   map[string]ptBootstrap   `json:"bootstraps"`
	Predecessors map[string]ptPredecessor `json:"predecessors"`
	Vectors      []ptVector               `json:"vectors"`
}

type ptVector struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Inputs struct {
		Repository            string            `json:"repository"`
		Component             string            `json:"component"`
		Authority             string            `json:"authority"`
		RangeMode             string            `json:"range_mode"`
		Boundary              *string           `json:"boundary"`
		VerificationProfile   string            `json:"verification_profile"`
		ClockProfile          string            `json:"clock_profile"`
		VerificationTime      string            `json:"verification_time"`
		ActivePolicy          string            `json:"active_policy"`
		CandidatePolicy       string            `json:"candidate_policy"`
		Bootstrap             *string           `json:"bootstrap"`
		Predecessor           *string           `json:"predecessor"`
		ProvidedTrustMaterial map[string]string `json:"provided_trust_material"`
		Commits               []struct {
			Signer string   `json:"signer"`
			Level  string   `json:"level"`
			Paths  []string `json:"paths"`
		} `json:"commits"`
	} `json:"inputs"`
	Expected struct {
		Outcome         string `json:"outcome"`
		Reason          string `json:"reason"`
		EvaluatedPolicy string `json:"evaluated_policy"`
		ActivatedPolicy string `json:"activated_policy"`
	} `json:"expected"`
}

func (d ptVectorFile) policy(t *testing.T, key string) MetaPolicy {
	t.Helper()
	p, ok := d.Policies[key]
	if !ok {
		t.Fatalf("policy %q not in doc", key)
	}
	return MetaPolicy(p)
}

func (d ptVectorFile) bootstrap(t *testing.T, key string) *BootstrapDescriptor {
	t.Helper()
	b, ok := d.Bootstraps[key]
	if !ok {
		t.Fatalf("bootstrap %q not in doc", key)
	}
	bd := BootstrapDescriptor(b)
	return &bd
}

func (d ptVectorFile) predecessor(t *testing.T, key string) *PredecessorPolicy {
	t.Helper()
	p, ok := d.Predecessors[key]
	if !ok {
		t.Fatalf("predecessor %q not in doc", key)
	}
	pp := PredecessorPolicy(p)
	return &pp
}

func loadPolicyTransitionVectors(t *testing.T) ptVectorFile {
	t.Helper()
	const name = "policy-transition.json"
	path := os.Getenv("SEMVER_TRUST_POLICY_TRANSITION_VECTORS")
	if path == "" {
		for _, candidate := range []string{
			filepath.Join("testdata", name),
			filepath.Join("..", "..", "conformance", "vendor", name),
		} {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		t.Fatalf("conformance vectors absent: conformance/vendor/%s missing (refresh via scripts/sync-conformance.py)", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading vectors %q: %v", path, err)
	}
	var vf ptVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parsing vectors %q: %v", path, err)
	}
	return vf
}
