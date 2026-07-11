// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"testing"

	"github.com/semver-trust/semver-trust-go/evidence"
	"github.com/semver-trust/semver-trust-go/internal/version"
)

func mustParse(t *testing.T, tag string) version.Version {
	t.Helper()
	v, err := version.Parse(tag)
	if err != nil {
		t.Fatalf("Parse(%q): %v", tag, err)
	}
	return v
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name string
		in   DecideInputs
		want string // expected tag; "" means escalate (no version asserted)
	}{
		{
			name: "T3/low patch goes clean",
			in: DecideInputs{
				Effective: T3, Blast: BlastLow, Strategy: StrategyDemote,
				DifferAvailable: true,
				SemanticFloor:   evidence.BumpPatch, ClaimedBump: evidence.BumpPatch,
				Current: mustParse(t, "v1.2.3"), Iteration: 1,
			},
			want: "v1.2.4",
		},
		{
			name: "T2/high demotes to the pre-release channel",
			in: DecideInputs{
				Effective: T2, Blast: BlastHigh, Strategy: StrategyDemote,
				DifferAvailable: true,
				SemanticFloor:   evidence.BumpPatch, ClaimedBump: evidence.BumpPatch,
				Current: mustParse(t, "v1.2.3"), Iteration: 1,
			},
			want: "v1.2.4-t2.1",
		},
		{
			name: "semantic floor overrides the claim: breaking at T3 is a major",
			in: DecideInputs{
				Effective: T3, Blast: BlastLow, Strategy: StrategyDemote,
				DifferAvailable: true,
				SemanticFloor:   evidence.BumpMajor, ClaimedBump: evidence.BumpPatch,
				Current: mustParse(t, "v1.2.3"), Iteration: 1,
			},
			want: "v2.0.0",
		},
		{
			name: "floor honored inside the pre-release channel too",
			in: DecideInputs{
				Effective: T0, Blast: BlastLow, Strategy: StrategyDemote,
				DifferAvailable: true,
				SemanticFloor:   evidence.BumpMajor, ClaimedBump: evidence.BumpPatch,
				Current: mustParse(t, "v1.2.3"), Iteration: 1,
			},
			want: "v2.0.0-t0.1",
		},
		{
			name: "component path carries into the decision",
			in: DecideInputs{
				Effective: T0, Blast: BlastModerate, Strategy: StrategyDemote,
				DifferAvailable: true,
				SemanticFloor:   evidence.BumpMinor, ClaimedBump: evidence.BumpMinor,
				Current: mustParse(t, "common/v0.8.4"), Iteration: 1,
			},
			want: "common/v0.9.0-t0.1",
		},
		{
			name: "re-cut increments the iteration",
			in: DecideInputs{
				Effective: T1, Blast: BlastModerate, Strategy: StrategyDemote,
				DifferAvailable: true,
				SemanticFloor:   evidence.BumpPatch, ClaimedBump: evidence.BumpPatch,
				Current: mustParse(t, "v1.2.3"), Iteration: 2,
			},
			want: "v1.2.4-t1.2",
		},
		{
			name: "inflate on a clean cell agrees with demote",
			in: DecideInputs{
				Effective: T3, Blast: BlastModerate, Strategy: StrategyInflate,
				DifferAvailable: true,
				SemanticFloor:   evidence.BumpMinor, ClaimedBump: evidence.BumpMinor,
				Current: mustParse(t, "v1.2.3"), Iteration: 1,
			},
			want: "v1.3.0",
		},
		{
			name: "inflate on a demoting cell escalates",
			in: DecideInputs{
				Effective: T0, Blast: BlastLow, Strategy: StrategyInflate,
				DifferAvailable: true,
				SemanticFloor:   evidence.BumpPatch, ClaimedBump: evidence.BumpPatch,
				Current: mustParse(t, "v1.2.3"), Iteration: 1,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(tt.in)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if tt.want == "" {
				if !got.Escalate || got.Channel != ChannelClean {
					t.Errorf("Decide = %+v, want escalation on the clean channel", got)
				}
				return
			}
			if got.Escalate {
				t.Errorf("Decide escalated unexpectedly: %+v", got)
			}
			if got.Version.String() != tt.want {
				t.Errorf("version = %s, want %s", got.Version, tt.want)
			}
		})
	}
}

// TestDecideHonestDegradation asserts the P4 clause the GO-025 acceptance
// names: where no differ is configured, every §6.4 "differ proof required"
// cell resolves to the pre-release channel — less verification capability
// means lower provable trust, never equal trust with less backing (§1.1).
func TestDecideHonestDegradation(t *testing.T) {
	differRequired := []struct {
		name  string
		level Level
		blast Blast
		bump  evidence.Bump
	}{
		{"T3/high patch claim", T3, BlastHigh, evidence.BumpPatch},
		{"T2/moderate patch claim", T2, BlastModerate, evidence.BumpPatch},
		{"T1/low any claim", T1, BlastLow, evidence.BumpMinor},
	}
	for _, tt := range differRequired {
		t.Run(tt.name, func(t *testing.T) {
			in := DecideInputs{
				Effective: tt.level, Blast: tt.blast, Strategy: StrategyDemote,
				DifferAvailable: false,
				SemanticFloor:   tt.bump, ClaimedBump: tt.bump,
				Current: mustParse(t, "v1.2.3"), Iteration: 1,
			}
			got, err := Decide(in)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if got.Channel != ChannelPrerelease {
				t.Errorf("channel = %s, want prerelease (differ required but unavailable)", got.Channel)
			}

			// The same cell goes clean the moment the differ exists: the
			// demotion above is the absence of proof, not the cell itself.
			in.DifferAvailable = true
			got, err = Decide(in)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if got.Channel != ChannelClean {
				t.Errorf("channel with differ = %s, want clean", got.Channel)
			}
		})
	}

	// The PATCH qualifier is real: a MINOR claim at T2/moderate needs no
	// differ.
	got, err := Decide(DecideInputs{
		Effective: T2, Blast: BlastModerate, Strategy: StrategyDemote,
		DifferAvailable: false,
		SemanticFloor:   evidence.BumpMinor, ClaimedBump: evidence.BumpMinor,
		Current: mustParse(t, "v1.2.3"), Iteration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Channel != ChannelClean {
		t.Errorf("T2/moderate minor without differ = %s, want clean (requirement qualifies PATCH claims)", got.Channel)
	}
}

func TestDecideRejects(t *testing.T) {
	base := DecideInputs{
		Effective: T3, Blast: BlastLow, Strategy: StrategyDemote,
		DifferAvailable: true,
		SemanticFloor:   evidence.BumpPatch, ClaimedBump: evidence.BumpPatch,
		Current: mustParse(t, "v1.2.3"), Iteration: 1,
	}

	t.Run("trust-suffixed current", func(t *testing.T) {
		in := base
		in.Current = mustParse(t, "v1.2.3-t2.1")
		if _, err := Decide(in); err == nil {
			t.Error("Decide accepted a trust-suffixed current version")
		}
	})
	t.Run("plain pre-release current", func(t *testing.T) {
		in := base
		in.Current = mustParse(t, "v1.2.3-rc.1")
		if _, err := Decide(in); err == nil {
			t.Error("Decide accepted a pre-release current version")
		}
	})
	t.Run("zero iteration", func(t *testing.T) {
		in := base
		in.Iteration = 0
		if _, err := Decide(in); err == nil {
			t.Error("Decide accepted iteration 0")
		}
	})
}
