// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"reflect"
	"testing"
)

func TestParseTrailers(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    Trailers
	}{
		{
			name: "provenance block",
			message: "feat: add thing\n\nBody text.\n\n" +
				"Provenance: agent\nProvenance-Agent: claude-code/2.1\nProvenance-Model: claude-fable-5\n",
			want: Trailers{
				{TrailerProvenance, "agent"},
				{TrailerProvenanceAgent, "claude-code/2.1"},
				{TrailerProvenanceModel, "claude-fable-5"},
			},
		},
		{
			name:    "subject plus trailers, no body",
			message: "feat: add thing\n\nProvenance: human\n",
			want:    Trailers{{TrailerProvenance, "human"}},
		},
		{
			name:    "subject only is never a trailer block",
			message: "Provenance: human\n",
			want:    nil,
		},
		{
			name:    "mixed final paragraph is prose, not trailers",
			message: "feat: x\n\nProvenance: agent\nand some prose\n",
			want:    nil,
		},
		{
			name: "repeated keys preserved in order",
			message: "feat: x\n\n" +
				"Co-authored-by: A <a@example.com>\nCo-authored-by: B <b@example.com>\n",
			want: Trailers{
				{TrailerCoAuthoredBy, "A <a@example.com>"},
				{TrailerCoAuthoredBy, "B <b@example.com>"},
			},
		},
		{
			name:    "folded continuation joins the previous value",
			message: "feat: x\n\nImported-From: go-semver\n @b427cc5\n",
			want:    Trailers{{"Imported-From", "go-semver @b427cc5"}},
		},
		{
			name:    "continuation without a preceding trailer is prose",
			message: "feat: x\n\n  indented prose\n",
			want:    nil,
		},
		{
			name:    "no blank separator means no block",
			message: "feat: x\nProvenance: human\n",
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseTrailers(tt.message)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTrailers = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrailersLookup(t *testing.T) {
	trailers := Trailers{
		{"Provenance", "human"},
		{"provenance", "agent"}, // later trailers override, case-insensitively
		{"Co-authored-by", "A <a@example.com>"},
		{"Co-Authored-By", "B <b@example.com>"},
	}

	if got := trailers.Provenance(); got != "agent" {
		t.Errorf("Provenance() = %q, want %q (last occurrence wins)", got, "agent")
	}
	if got, ok := trailers.Get("PROVENANCE"); !ok || got != "agent" {
		t.Errorf("Get(PROVENANCE) = %q,%v", got, ok)
	}
	if _, ok := trailers.Get("Missing"); ok {
		t.Error("Get(Missing) reported present")
	}
	coauthors := trailers.Values("co-authored-by")
	if len(coauthors) != 2 {
		t.Errorf("Values(co-authored-by) = %v, want 2 entries", coauthors)
	}
	if (Trailers)(nil).Provenance() != "" {
		t.Error("nil Trailers Provenance() != \"\"")
	}
}
