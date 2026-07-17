// SPDX-License-Identifier: Apache-2.0

package version

import (
	"strings"
	"testing"
)

// CanonicalStateMap must reproduce the ADR-036 canonical object the spec
// conformance vectors pin: building a VersionState equal to a vector's
// inputs.state and digesting it yields the vector's expected digest. This links
// the VersionState→canonical-object bridge to the same digests the spec oracle
// verifies (conformance/vendor/version-state-canonicalization.json).
func TestCanonicalStateMapMatchesVectors(t *testing.T) {
	commit := strings.Repeat("c", 40)

	t.Run("genesis-advance", func(t *testing.T) {
		st := VersionState{
			Baseline:        nil,
			BaselineCore:    "0.0.0",
			TargetCore:      "0.1.0",
			TargetBump:      "minor",
			CleanAccepted:   false,
			TargetIntervals: []string{GenesisIntervalID("auth", "inception")},
			Iterations:      map[string]int{"T2": 1},
		}
		got, err := StateDigest(CanonicalStateMap("auth", "auth/", st, nil))
		if err != nil {
			t.Fatal(err)
		}
		const want = "4fb3ad49a90ae21dc8044b5dcab5d3f3543fbd156b704776d0096a6e5071ad4f"
		if got != want {
			t.Errorf("genesis digest = %s, want the pinned vector digest %s", got, want)
		}
	})

	t.Run("recurring-advance-chained", func(t *testing.T) {
		predecessor := "sha256:4fb3ad49a90ae21dc8044b5dcab5d3f3543fbd156b704776d0096a6e5071ad4f"
		st := VersionState{
			Baseline:        &Binding{Tag: "auth/v0.1.0-t2.1", RefOID: strings.Repeat("1", 40), CommitOID: commit},
			BaselineCore:    "0.1.0",
			TargetCore:      "0.2.0",
			TargetBump:      "minor",
			CleanAccepted:   false,
			TargetIntervals: []string{"interval:auth:recurring:2"},
			Iterations:      map[string]int{"T2": 1},
		}
		got, err := StateDigest(CanonicalStateMap("auth", "auth/", st, &predecessor))
		if err != nil {
			t.Fatal(err)
		}
		const want = "f19fbbd6c3ee325887c5a121f72a2d685576a223a43aaf62d589e0993b1d1763"
		if got != want {
			t.Errorf("recurring digest = %s, want the pinned vector digest %s", got, want)
		}
	})
}

func TestGenesisIntervalID(t *testing.T) {
	if got := GenesisIntervalID("auth", "inception"); got != "interval:auth:inception:1" {
		t.Errorf("GenesisIntervalID = %q, want interval:auth:inception:1", got)
	}
	if GenesisIntervalID("auth", "inception") == GenesisIntervalID("auth", "adoption") {
		t.Error("interval id does not distinguish inception from adoption")
	}
}
