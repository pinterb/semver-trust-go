// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"testing"

	"github.com/semver-trust/semver-trust-go/evidence"
	"github.com/semver-trust/semver-trust-go/internal/version"
)

// Consumes the decision conformance vectors when reachable, per the GO-020
// precedent (the durable vendored harness is GO-026): set
// SEMVER_TRUST_DECISION_VECTORS or drop them at testdata/decision.json;
// absent both, skip.

func TestConformanceDecision(t *testing.T) {
	vf := loadAggVectors(t, "SEMVER_TRUST_DECISION_VECTORS", "decision.json")

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "decision" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			var inputs struct {
				EffectiveTrust  string `json:"effective_trust"`
				Blast           string `json:"blast"`
				Strategy        string `json:"strategy"`
				DifferAvailable bool   `json:"differ_available"`
				SemanticFloor   string `json:"semantic_floor"`
				ClaimedBump     string `json:"claimed_bump"`
				CurrentVersion  string `json:"current_version"`
				Iteration       uint64 `json:"iteration"`
			}
			var expected struct {
				Channel  string  `json:"channel"`
				Bump     *string `json:"bump"`
				Version  *string `json:"version"`
				Escalate *bool   `json:"escalate"`
			}
			decode(t, vec.Inputs, &inputs)
			decode(t, vec.Expected, &expected)

			current, err := version.Parse(inputs.CurrentVersion)
			if err != nil {
				t.Fatalf("Parse(%q): %v", inputs.CurrentVersion, err)
			}
			in := DecideInputs{
				Effective:       mustLevel(t, inputs.EffectiveTrust),
				DifferAvailable: inputs.DifferAvailable,
				Current:         current,
				Iteration:       inputs.Iteration,
			}
			if in.Blast, err = ParseBlast(inputs.Blast); err != nil {
				t.Fatal(err)
			}
			if in.Strategy, err = ParseStrategy(inputs.Strategy); err != nil {
				t.Fatal(err)
			}
			if in.SemanticFloor, err = evidence.ParseBump(inputs.SemanticFloor); err != nil {
				t.Fatal(err)
			}
			if in.ClaimedBump, err = evidence.ParseBump(inputs.ClaimedBump); err != nil {
				t.Fatal(err)
			}

			got, err := Decide(in)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}

			if got.Channel.String() != expected.Channel {
				t.Errorf("channel = %s, want %s", got.Channel, expected.Channel)
			}
			if wantEscalate := expected.Escalate != nil && *expected.Escalate; got.Escalate != wantEscalate {
				t.Errorf("escalate = %v, want %v", got.Escalate, wantEscalate)
			}
			// Escalated inflate outcomes assert no bump/version: the
			// escalation target is a policy choice the spec does not pin.
			if expected.Bump != nil && got.Bump.String() != *expected.Bump {
				t.Errorf("bump = %s, want %s", got.Bump, *expected.Bump)
			}
			if expected.Version != nil && got.Version.String() != *expected.Version {
				t.Errorf("version = %s, want %s", got.Version, *expected.Version)
			}
		})
	}
	if seen == 0 {
		t.Error("no decision vectors found")
	}
}
