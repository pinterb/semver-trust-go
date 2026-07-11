// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The conformance vectors are the spec repository's acceptance suite. This
// smoke test consumes them when they are reachable but stays hermetic: the
// durable, version-pinned harness that vendors the vectors is GO-026. Point
// it at the vectors with SEMVER_TRUST_LEVELS_VECTORS, or drop them at
// testdata/levels.json; absent both, the test skips.

type vectorFile struct {
	SpecVersion string   `json:"spec_version"`
	Vectors     []vector `json:"vectors"`
}

type vector struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Inputs   inputs   `json:"inputs"`
	Expected expected `json:"expected"`
}

type inputs struct {
	// matrix inputs
	Authorship string `json:"authorship"`
	Review     string `json:"review"`

	// classify inputs
	SignerIdentityClass string        `json:"signer_identity_class"`
	Trailers            trailers      `json:"trailers"`
	Policy              policy        `json:"policy"`
	ReviewFacts         *reviewInputs `json:"-"`
}

// classify vectors carry "review" as an object-or-null while matrix vectors
// carry it as a string; a custom unmarshaller keeps both shapes in one type.
func (in *inputs) UnmarshalJSON(data []byte) error {
	type alias inputs
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		// Retry with the object-shaped review.
		var obj struct {
			alias
			Review *reviewInputs `json:"review"`
		}
		if err2 := json.Unmarshal(data, &obj); err2 != nil {
			return err
		}
		*in = inputs(obj.alias)
		in.ReviewFacts = obj.Review
		return nil
	}
	*in = inputs(a)
	return nil
}

type trailers struct {
	Provenance string `json:"Provenance"`
}

type policy struct {
	TrailersRequire bool `json:"trailers_require"`
}

type reviewInputs struct {
	ReviewerIdentityClass string `json:"reviewer_identity_class"`
	ReviewerIdentity      string `json:"reviewer_identity"`
	AuthorIdentity        string `json:"author_identity"`
	SeparateContext       bool   `json:"separate_context"`
	SignedAttestation     bool   `json:"signed_attestation"`
}

type expected struct {
	Authorship string `json:"authorship"`
	Review     string `json:"review"`
	Level      string `json:"level"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()

	path := os.Getenv("SEMVER_TRUST_LEVELS_VECTORS")
	if path == "" {
		candidate := filepath.Join("testdata", "levels.json")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
		}
	}
	if path == "" {
		t.Skip("conformance vectors absent; set SEMVER_TRUST_LEVELS_VECTORS or vendor testdata/levels.json (GO-026)")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading vectors %q: %v", path, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parsing vectors %q: %v", path, err)
	}
	return vf
}

func parseAuthorship(t *testing.T, s string) Authorship {
	t.Helper()
	switch s {
	case "agent":
		return AuthorshipAgent
	case "mixed":
		return AuthorshipMixed
	case "ambiguous":
		return AuthorshipAmbiguous
	case "human":
		return AuthorshipHuman
	default:
		t.Fatalf("unknown authorship class %q", s)
		return 0
	}
}

func parseReview(t *testing.T, s string) Review {
	t.Helper()
	switch s {
	case "none":
		return ReviewNone
	case "agent_independent":
		return ReviewAgentIndependent
	case "human_distinct":
		return ReviewHumanDistinct
	case "human_same_identity":
		return ReviewHumanSameIdentity
	default:
		t.Fatalf("unknown review class %q", s)
		return 0
	}
}

func parseIdentityClass(t *testing.T, s string) IdentityClass {
	t.Helper()
	switch s {
	case "human":
		return IdentityHuman
	case "agent":
		return IdentityAgent
	default:
		t.Fatalf("unknown identity class %q", s)
		return 0
	}
}

func TestConformanceMatrix(t *testing.T) {
	vf := loadVectors(t)

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "matrix" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			a := parseAuthorship(t, vec.Inputs.Authorship)
			r := parseReview(t, vec.Inputs.Review)
			if got := AssignLevel(a, r).String(); got != vec.Expected.Level {
				t.Errorf("AssignLevel(%s, %s) = %s, want %s",
					vec.Inputs.Authorship, vec.Inputs.Review, got, vec.Expected.Level)
			}
		})
	}
	if seen == 0 {
		t.Error("no matrix vectors found")
	}
}

func TestConformanceClassify(t *testing.T) {
	vf := loadVectors(t)

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "classify" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			facts := CommitFacts{
				Signer:           parseIdentityClass(t, vec.Inputs.SignerIdentityClass),
				Provenance:       vec.Inputs.Trailers.Provenance,
				TrailersRequired: vec.Inputs.Policy.TrailersRequire,
			}
			if rf := vec.Inputs.ReviewFacts; rf != nil {
				facts.Review = &ReviewFacts{
					Reviewer:          parseIdentityClass(t, rf.ReviewerIdentityClass),
					ReviewerIdentity:  rf.ReviewerIdentity,
					AuthorIdentity:    rf.AuthorIdentity,
					SeparateContext:   rf.SeparateContext,
					SignedAttestation: rf.SignedAttestation,
				}
			}

			a, r, l := Classify(facts)
			if a.String() != vec.Expected.Authorship {
				t.Errorf("authorship = %s, want %s", a, vec.Expected.Authorship)
			}
			if r.String() != vec.Expected.Review {
				t.Errorf("review = %s, want %s", r, vec.Expected.Review)
			}
			if l.String() != vec.Expected.Level {
				t.Errorf("level = %s, want %s", l, vec.Expected.Level)
			}
		})
	}
	if seen == 0 {
		t.Error("no classify vectors found")
	}
}
