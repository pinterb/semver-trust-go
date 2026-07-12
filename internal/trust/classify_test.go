// SPDX-License-Identifier: Apache-2.0

package trust

import "testing"

// TestClassify covers the §3.2/§3.3/§4.1 classification rules. The cases
// mirror the levels.json classify vectors (see conformance_test.go) plus the
// spec-derived cases the vectors leave unpinned: an agent trailer under a
// human signer (the §4.2 local-use case), a bare signer with no mandating
// policy, an unrecognized trailer value, and an unattested human review.
func TestClassify(t *testing.T) {
	tests := []struct {
		name           string
		facts          CommitFacts
		wantAuthorship Authorship
		wantReview     Review
		wantLevel      Level
	}{
		{
			// §4.1 rule 1: a human claim on a machine identity is ambiguous.
			name: "human provenance, machine signer",
			facts: CommitFacts{
				Signer:     IdentityAgent,
				Provenance: ProvenanceHuman,
			},
			wantAuthorship: AuthorshipAmbiguous,
			wantReview:     ReviewNone,
			wantLevel:      T0,
		},
		{
			// §3.2 note 1: required trailers absent under a mandating policy.
			name: "trailers absent under mandating policy",
			facts: CommitFacts{
				Signer:           IdentityHuman,
				TrailersRequired: true,
			},
			wantAuthorship: AuthorshipAmbiguous,
			wantReview:     ReviewNone,
			wantLevel:      T0,
		},
		{
			// Absent trailer without a mandating policy: the signer identity
			// class alone governs.
			name: "trailers absent, no mandate, human signer",
			facts: CommitFacts{
				Signer: IdentityHuman,
			},
			wantAuthorship: AuthorshipHuman,
			wantReview:     ReviewNone,
			wantLevel:      T2,
		},
		{
			name: "trailers absent, no mandate, agent signer",
			facts: CommitFacts{
				Signer: IdentityAgent,
			},
			wantAuthorship: AuthorshipAgent,
			wantReview:     ReviewNone,
			wantLevel:      T0,
		},
		{
			// §4.2 local-use case: conceding agent authorship under a human
			// key is honest and classifies as agent.
			name: "agent provenance, human signer",
			facts: CommitFacts{
				Signer:     IdentityHuman,
				Provenance: ProvenanceAgent,
			},
			wantAuthorship: AuthorshipAgent,
			wantReview:     ReviewNone,
			wantLevel:      T0,
		},
		{
			// An unrecognized trailer value is an unverifiable claim.
			name: "unrecognized provenance value",
			facts: CommitFacts{
				Signer:     IdentityHuman,
				Provenance: "vibes",
			},
			wantAuthorship: AuthorshipAmbiguous,
			wantReview:     ReviewNone,
			wantLevel:      T0,
		},
		{
			name: "mixed provenance floors to the agent row",
			facts: CommitFacts{
				Signer:     IdentityHuman,
				Provenance: ProvenanceMixed,
			},
			wantAuthorship: AuthorshipMixed,
			wantReview:     ReviewNone,
			wantLevel:      T0,
		},
		{
			name: "consistent agent signer and trailer",
			facts: CommitFacts{
				Signer:           IdentityAgent,
				Provenance:       ProvenanceAgent,
				TrailersRequired: true,
			},
			wantAuthorship: AuthorshipAgent,
			wantReview:     ReviewNone,
			wantLevel:      T0,
		},
		{
			name: "consistent human signer and trailer",
			facts: CommitFacts{
				Signer:           IdentityHuman,
				Provenance:       ProvenanceHuman,
				TrailersRequired: true,
			},
			wantAuthorship: AuthorshipHuman,
			wantReview:     ReviewNone,
			wantLevel:      T2,
		},
		{
			// §3.3 condition 2: same identity cannot corroborate itself.
			name: "agent review by the author's identity",
			facts: CommitFacts{
				Signer:     IdentityAgent,
				Provenance: ProvenanceAgent,
				Review: &ReviewFacts{
					Reviewer:          IdentityAgent,
					ReviewerIdentity:  "agent-a",
					SignerIdentity:    "agent-a",
					SeparateContext:   true,
					SignedAttestation: true,
				},
			},
			wantAuthorship: AuthorshipAgent,
			wantReview:     ReviewNone,
			wantLevel:      T0,
		},
		{
			// §3.3 condition 1: shared context disqualifies.
			name: "agent review sharing context",
			facts: CommitFacts{
				Signer:     IdentityAgent,
				Provenance: ProvenanceAgent,
				Review: &ReviewFacts{
					Reviewer:          IdentityAgent,
					ReviewerIdentity:  "agent-b",
					SignerIdentity:    "agent-a",
					SeparateContext:   false,
					SignedAttestation: true,
				},
			},
			wantAuthorship: AuthorshipAgent,
			wantReview:     ReviewNone,
			wantLevel:      T0,
		},
		{
			// §3.3 condition 3: no signed attestation disqualifies.
			name: "agent review without attestation",
			facts: CommitFacts{
				Signer:     IdentityAgent,
				Provenance: ProvenanceAgent,
				Review: &ReviewFacts{
					Reviewer:          IdentityAgent,
					ReviewerIdentity:  "agent-b",
					SignerIdentity:    "agent-a",
					SeparateContext:   true,
					SignedAttestation: false,
				},
			},
			wantAuthorship: AuthorshipAgent,
			wantReview:     ReviewNone,
			wantLevel:      T0,
		},
		{
			// All three §3.3 conditions hold: independent agent review.
			name: "independent agent review",
			facts: CommitFacts{
				Signer:     IdentityAgent,
				Provenance: ProvenanceAgent,
				Review: &ReviewFacts{
					Reviewer:          IdentityAgent,
					ReviewerIdentity:  "agent-b",
					SignerIdentity:    "agent-a",
					SeparateContext:   true,
					SignedAttestation: true,
				},
			},
			wantAuthorship: AuthorshipAgent,
			wantReview:     ReviewAgentIndependent,
			wantLevel:      T1,
		},
		{
			// §3.2 note 2: self-review is not review.
			name: "human self-review",
			facts: CommitFacts{
				Signer:     IdentityHuman,
				Provenance: ProvenanceHuman,
				Review: &ReviewFacts{
					Reviewer:          IdentityHuman,
					ReviewerIdentity:  "alice@example.com",
					SignerIdentity:    "alice@example.com",
					SeparateContext:   true,
					SignedAttestation: true,
				},
			},
			wantAuthorship: AuthorshipHuman,
			wantReview:     ReviewNone,
			wantLevel:      T2,
		},
		{
			// Human review counts only once captured as a signed attestation
			// (§4.3): an unattested review is an unverifiable claim.
			name: "human review without attestation",
			facts: CommitFacts{
				Signer:     IdentityHuman,
				Provenance: ProvenanceHuman,
				Review: &ReviewFacts{
					Reviewer:          IdentityHuman,
					ReviewerIdentity:  "bob@example.com",
					SignerIdentity:    "alice@example.com",
					SeparateContext:   true,
					SignedAttestation: false,
				},
			},
			wantAuthorship: AuthorshipHuman,
			wantReview:     ReviewNone,
			wantLevel:      T2,
		},
		{
			name: "distinct human review",
			facts: CommitFacts{
				Signer:     IdentityHuman,
				Provenance: ProvenanceHuman,
				Review: &ReviewFacts{
					Reviewer:          IdentityHuman,
					ReviewerIdentity:  "bob@example.com",
					SignerIdentity:    "alice@example.com",
					SeparateContext:   true,
					SignedAttestation: true,
				},
			},
			wantAuthorship: AuthorshipHuman,
			wantReview:     ReviewHumanDistinct,
			wantLevel:      T3,
		},
		{
			// ADR-025: the self-review exclusion prevents one human counting
			// twice, never once — honestly agent-trailered work reviewed by
			// its own signer gains its first accountable human.
			name: "agent-trailered commit reviewed by its signer",
			facts: CommitFacts{
				Signer:           IdentityHuman,
				Provenance:       ProvenanceAgent,
				TrailersRequired: true,
				Review: &ReviewFacts{
					Reviewer:          IdentityHuman,
					ReviewerIdentity:  "alice@example.com",
					SignerIdentity:    "alice@example.com",
					SignedAttestation: true,
				},
			},
			wantAuthorship: AuthorshipAgent,
			wantReview:     ReviewHumanDistinct,
			wantLevel:      T2,
		},
		{
			name: "mixed commit reviewed by its signer",
			facts: CommitFacts{
				Signer:           IdentityHuman,
				Provenance:       ProvenanceMixed,
				TrailersRequired: true,
				Review: &ReviewFacts{
					Reviewer:          IdentityHuman,
					ReviewerIdentity:  "alice@example.com",
					SignerIdentity:    "alice@example.com",
					SignedAttestation: true,
				},
			},
			wantAuthorship: AuthorshipMixed,
			wantReview:     ReviewHumanDistinct,
			wantLevel:      T2,
		},
		{
			name: "ambiguous commit reviewed by its signer",
			facts: CommitFacts{
				Signer:           IdentityAgent,
				Provenance:       ProvenanceHuman,
				TrailersRequired: true,
				Review: &ReviewFacts{
					Reviewer:          IdentityHuman,
					ReviewerIdentity:  "release-bot@acme.dev",
					SignerIdentity:    "release-bot@acme.dev",
					SignedAttestation: true,
				},
			},
			wantAuthorship: AuthorshipAmbiguous,
			wantReview:     ReviewHumanDistinct,
			wantLevel:      T2,
		},
		{
			// Human review needs no separate execution context — §3.3(1) is
			// an agent-review condition.
			name: "distinct human review without separate context",
			facts: CommitFacts{
				Signer:     IdentityHuman,
				Provenance: ProvenanceHuman,
				Review: &ReviewFacts{
					Reviewer:          IdentityHuman,
					ReviewerIdentity:  "bob@example.com",
					SignerIdentity:    "alice@example.com",
					SeparateContext:   false,
					SignedAttestation: true,
				},
			},
			wantAuthorship: AuthorshipHuman,
			wantReview:     ReviewHumanDistinct,
			wantLevel:      T3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, r, l := Classify(tt.facts)
			if a != tt.wantAuthorship || r != tt.wantReview || l != tt.wantLevel {
				t.Errorf("Classify() = (%s, %s, %s), want (%s, %s, %s)",
					a, r, l, tt.wantAuthorship, tt.wantReview, tt.wantLevel)
			}
		})
	}
}
