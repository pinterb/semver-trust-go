// SPDX-License-Identifier: Apache-2.0

package trust

import "testing"

// TestAssignLevelMatrix encodes the full §3.2 authorship × review matrix,
// including the self-review row (§3.2 note 2). It mirrors the levels.json
// matrix vectors so the level function is pinned even when the vendored
// vectors are absent (see conformance_test.go).
func TestAssignLevelMatrix(t *testing.T) {
	tests := []struct {
		authorship Authorship
		review     Review
		want       Level
	}{
		{AuthorshipAgent, ReviewNone, T0},
		{AuthorshipAgent, ReviewAgentIndependent, T1},
		{AuthorshipAgent, ReviewHumanDistinct, T2},
		{AuthorshipMixed, ReviewNone, T0},
		{AuthorshipMixed, ReviewAgentIndependent, T1},
		{AuthorshipMixed, ReviewHumanDistinct, T2},
		{AuthorshipAmbiguous, ReviewNone, T0},
		{AuthorshipAmbiguous, ReviewAgentIndependent, T1},
		{AuthorshipAmbiguous, ReviewHumanDistinct, T2},
		{AuthorshipHuman, ReviewNone, T2},
		{AuthorshipHuman, ReviewAgentIndependent, T2},
		{AuthorshipHuman, ReviewHumanDistinct, T3},
		{AuthorshipHuman, ReviewHumanSameIdentity, T2},

		// Self-review contributes nothing on any row, not only the human one
		// (Appendix B: self-review = none).
		{AuthorshipAgent, ReviewHumanSameIdentity, T0},
		{AuthorshipMixed, ReviewHumanSameIdentity, T0},
		{AuthorshipAmbiguous, ReviewHumanSameIdentity, T0},
	}
	for _, tt := range tests {
		t.Run(tt.authorship.String()+"/"+tt.review.String(), func(t *testing.T) {
			if got := AssignLevel(tt.authorship, tt.review); got != tt.want {
				t.Errorf("AssignLevel(%s, %s) = %s, want %s",
					tt.authorship, tt.review, got, tt.want)
			}
		})
	}
}

func TestLevelStrings(t *testing.T) {
	tests := []struct {
		level Level
		want  string
	}{
		{T0, "T0"},
		{T1, "T1"},
		{T2, "T2"},
		{T3, "T3"},
		{Level(9), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.level.String(); got != tt.want {
			t.Errorf("Level(%d).String() = %q, want %q", tt.level, got, tt.want)
		}
	}
}

// TestLevelOrdering pins that the numeric values order T0 < T1 < T2 < T3, the
// property min-flooring (§5.2, §5.3) will rely on.
func TestLevelOrdering(t *testing.T) {
	if T0 >= T1 || T1 >= T2 || T2 >= T3 {
		t.Errorf("levels are not ordered: T0=%d T1=%d T2=%d T3=%d", T0, T1, T2, T3)
	}
}
