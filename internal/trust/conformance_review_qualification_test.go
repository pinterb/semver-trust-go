// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConformanceReviewQualification drives the spec's review-qualification
// vectors (§4.3, ADR-031) through QualifyReview + AssignLevel: only an
// approved, active, revision-bound, canonically-distinct (and, for agents,
// independent) review raises trust, and each disqualification reports a stable
// reason.
func TestConformanceReviewQualification(t *testing.T) {
	vf := loadRQVectors(t)
	if vf.SpecVersion == "" {
		t.Fatal("review-qualification vectors missing spec_version")
	}
	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "review_qualification" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			author := parseAuthorship(t, vec.Inputs.Authorship.Class)
			q := ReviewQualification{
				ReviewerClass:      parseIdentityClass(t, vec.Inputs.Review.Class),
				ReviewerActor:      vec.Inputs.Review.Actor,
				AuthorActor:        vec.Inputs.Authorship.Actor,
				CredentialActor:    vec.Inputs.Review.CredentialActor,
				Verdict:            vec.Inputs.Review.Verdict,
				ApprovalState:      vec.Inputs.Review.ApprovalState,
				EffectiveAtMerge:   vec.Inputs.Review.EffectiveAtMerge,
				Coverage:           vec.Inputs.Review.Coverage,
				ApprovedRevision:   vec.Inputs.Review.ApprovedRevision,
				FinalRevision:      vec.Inputs.Review.FinalRevision,
				ApprovedDiff:       vec.Inputs.Review.ApprovedDiff,
				ResultDiff:         vec.Inputs.Review.ResultDiff,
				MergeStrategy:      vec.Inputs.Merge.Strategy,
				CaptureMode:        vec.Inputs.Merge.CaptureMode,
				SeparateContext:    vec.Inputs.Review.SeparateContext,
				PostApprovalChange: vec.Inputs.Merge.PostApprovalChange,
				SignedAttestation:  vec.Inputs.Review.SignedAttestation,
			}
			review, reason := QualifyReview(author, q)
			level := AssignLevel(author, review)

			if got := review.String(); got != vec.Expected.Review {
				t.Errorf("review = %s, want %s", got, vec.Expected.Review)
			}
			if got := level.String(); got != vec.Expected.Level {
				t.Errorf("level = %s, want %s", got, vec.Expected.Level)
			}
			if reason != vec.Expected.Reason {
				t.Errorf("reason = %q, want %q", reason, vec.Expected.Reason)
			}
		})
	}
	if seen == 0 {
		t.Fatal("no review_qualification vectors ran")
	}
}

type rqVectorFile struct {
	SpecVersion string     `json:"spec_version"`
	Vectors     []rqVector `json:"vectors"`
}

type rqVector struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Inputs struct {
		Authorship struct {
			Class string `json:"class"`
			Actor string `json:"actor"`
		} `json:"authorship"`
		Review struct {
			Class             string `json:"class"`
			Actor             string `json:"actor"`
			CredentialActor   string `json:"credential_actor"`
			Verdict           string `json:"verdict"`
			ApprovalState     string `json:"approval_state"`
			Coverage          string `json:"coverage"`
			ApprovedRevision  string `json:"approved_revision"`
			FinalRevision     string `json:"final_revision"`
			ApprovedDiff      string `json:"approved_diff"`
			ResultDiff        string `json:"result_diff"`
			EffectiveAtMerge  bool   `json:"effective_at_merge"`
			SignedAttestation bool   `json:"signed_attestation"`
			SeparateContext   bool   `json:"separate_context"`
		} `json:"review"`
		Merge struct {
			Strategy           string `json:"strategy"`
			CaptureMode        string `json:"capture_mode"`
			PostApprovalChange bool   `json:"post_approval_change"`
		} `json:"merge"`
	} `json:"inputs"`
	Expected struct {
		Review string `json:"review"`
		Level  string `json:"level"`
		Reason string `json:"reason"`
	} `json:"expected"`
}

func loadRQVectors(t *testing.T) rqVectorFile {
	t.Helper()
	const name = "review-qualification.json"
	path := os.Getenv("SEMVER_TRUST_REVIEW_QUALIFICATION_VECTORS")
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
	var vf rqVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parsing vectors %q: %v", path, err)
	}
	return vf
}
