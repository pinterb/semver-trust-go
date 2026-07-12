// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

func releaseSchemaBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vendorDir(t), "schemas", "release-v0.1.json"))
	if err != nil {
		t.Fatalf("reading release schema: %v", err)
	}
	return data
}

func intPtr(v int) *int { return &v }

// validReleaseInput is the fixture-shaped §8.1 input: a first release
// (range.from null), self-floored trust (floor_source null), no differ, an
// operator-supplied blast score, and an original decision (supersedes null).
func validReleaseInput() ReleaseInput {
	return ReleaseInput{
		Tag:       "v0.1.1",
		CommitSHA: "80e2be6297494cd2e3c85d2ace1c7579edac3f74",
		Component: "default",
		Effective: "T2",
		Own:       "T2",
		Commits: []ReleaseCommit{
			{
				SHA:              "e076050f6714ea6be852fce9c47ff65b05c911b3",
				Level:            "T3",
				AuthorshipClass:  "human",
				SignerIdentity:   "alice@semver-trust.test",
				Trailers:         map[string]string{"Provenance": "human"},
				ReviewClass:      "human",
				ReviewerIdentity: "bob@semver-trust.test",
				ReviewAttestation: "refs/attestations/e076050f6714ea6be852fce9c47ff65b05c911b3/0123456789abcdef01234567",
			},
			{
				SHA:             "80e2be6297494cd2e3c85d2ace1c7579edac3f74",
				Level:           "T0",
				AuthorshipClass: "agent",
				SignerIdentity:  "ci-bot@semver-trust.test",
				Trailers:        map[string]string{"Provenance": "agent", "Provenance-Agent": "fixture-agent/1.0"},
				ReviewClass:     "none",
			},
		},
		Blast: ReleaseBlast{
			Files: intPtr(2),
			Score: "low",
			Inputs: map[string]any{
				"source":        "operator",
				"changed_files": 2,
			},
		},
		Decision: ReleaseDecision{
			ClaimedBump:   "patch",
			SemanticFloor: "patch",
			Strategy:      "demote",
			Channel:       "prerelease",
			PolicyPath:    ".semver-trust/policy.toml",
			PolicyDigest:  "sha256:6c8571e5f775f43b7e1c46e1bbaf7cd28d7e29b1f2e01b74f9c4b23e64e0aad9",
		},
		Timestamp: emitEpoch,
	}
}

// An emitted release envelope verifies through an INDEPENDENT verifier and
// its payload carries the §8.1 null-vs-value distinctions exactly: range.from
// null for a first release, floor_source null when self-floored,
// dependencies_pinned present-and-empty, supersedes null, and no
// from_is_adoption_boundary key at all when no boundary anchored the range.
func TestReleaseEmitVerifiesIndependently(t *testing.T) {
	signer := newEmitTestSigner(t)
	emitter, err := NewReleaseEmitter(signer, releaseSchemaBytes(t))
	if err != nil {
		t.Fatalf("NewReleaseEmitter: %v", err)
	}
	emission, err := emitter.Emit(validReleaseInput())
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if emission.KeyID != emitter.Signer() {
		t.Errorf("KeyID = %s, want %s", emission.KeyID, emitter.Signer())
	}

	independent, err := NewVerifier([]sshsig.AllowedSigner{{
		Principals: []string{"release-workflow@semver-trust.test"},
		Namespaces: []string{Namespace},
		Key:        signer.PublicKey(),
	}}, map[string][]byte{PredicateRelease: releaseSchemaBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := independent.Verify(emission.Envelope, emitEpoch)
	if err != nil {
		t.Fatalf("independent verification: %v", err)
	}
	if stmt.PredicateType != PredicateRelease {
		t.Errorf("predicate type = %s", stmt.PredicateType)
	}
	if len(stmt.Subjects) != 1 || stmt.Subjects[0].Name != "v0.1.1" ||
		stmt.Subjects[0].Digest["gitCommit"] != "80e2be6297494cd2e3c85d2ace1c7579edac3f74" {
		t.Errorf("subjects = %+v, want the tag bound to the TO commit (§8.1)", stmt.Subjects)
	}

	// The null-vs-value shape is part of the frozen bytes: assert on the raw
	// payload, not a lossy re-unmarshal.
	var predicate struct {
		Range              map[string]json.RawMessage `json:"range"`
		Trust              map[string]json.RawMessage `json:"trust"`
		Decision           map[string]json.RawMessage `json:"decision"`
	}
	var payload struct {
		Predicate json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(emission.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload.Predicate, &predicate); err != nil {
		t.Fatal(err)
	}
	if got := string(predicate.Range["from"]); got != "null" {
		t.Errorf("range.from = %s, want null (first release, §5.2)", got)
	}
	if _, present := predicate.Range["from_is_adoption_boundary"]; present {
		t.Error("from_is_adoption_boundary present without a boundary (ADR-026: disclose only what holds)")
	}
	if got := string(predicate.Trust["floor_source"]); got != "null" {
		t.Errorf("trust.floor_source = %s, want null (self-floored, §5.3)", got)
	}
	if got := string(predicate.Trust["dependencies_pinned"]); got != "[]" {
		t.Errorf("trust.dependencies_pinned = %s, want [] (present, empty)", got)
	}
	if got := string(predicate.Decision["supersedes"]); got != "null" {
		t.Errorf("decision.supersedes = %s, want null (original decision, §7.3)", got)
	}
}

// A boundary-anchored release carries the ADR-026 disclosure: range.from is
// the boundary and from_is_adoption_boundary is true — and the payload still
// validates against the vendored release-v0.1.json.
func TestReleaseEmitDisclosesAdoptionBoundary(t *testing.T) {
	in := validReleaseInput()
	in.RangeFrom = "v0-import"
	in.FromIsAdoptionBoundary = true

	emitter, err := NewReleaseEmitter(newEmitTestSigner(t), releaseSchemaBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	emission, err := emitter.Emit(in)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	var payload struct {
		Predicate struct {
			Range struct {
				From                   *string `json:"from"`
				FromIsAdoptionBoundary bool    `json:"from_is_adoption_boundary"`
			} `json:"range"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(emission.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Predicate.Range.From == nil || *payload.Predicate.Range.From != "v0-import" {
		t.Errorf("range.from = %v, want the boundary revision", payload.Predicate.Range.From)
	}
	if !payload.Predicate.Range.FromIsAdoptionBoundary {
		t.Error("from_is_adoption_boundary = false, want true (ADR-026 disclosure)")
	}
}

// The refuse-to-sign gate: a payload that violates release-v0.1.json is
// refused BEFORE signing (an out-of-vocabulary level here), and inputs that
// cannot form a statement at all are refused earlier still.
func TestReleaseEmitRefusals(t *testing.T) {
	emitter, err := NewReleaseEmitter(newEmitTestSigner(t), releaseSchemaBytes(t))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("schema-invalid level refused before signing", func(t *testing.T) {
		in := validReleaseInput()
		in.Effective = "T9"
		_, err := emitter.Emit(in)
		if !errors.Is(err, ErrSchemaInvalid) {
			t.Fatalf("Emit = %v, want ErrSchemaInvalid", err)
		}
		if !strings.Contains(err.Error(), "refusing to sign") {
			t.Errorf("error %q does not name the refuse-to-sign gate", err)
		}
	})

	for name, mutate := range map[string]func(*ReleaseInput){
		"no tag":            func(in *ReleaseInput) { in.Tag = "" },
		"no commit sha":     func(in *ReleaseInput) { in.CommitSHA = "" },
		"no component":      func(in *ReleaseInput) { in.Component = "" },
		"empty vector":      func(in *ReleaseInput) { in.Commits = nil },
		"zero timestamp":    func(in *ReleaseInput) { in.Timestamp = time.Time{} },
		"boundary, no from": func(in *ReleaseInput) { in.FromIsAdoptionBoundary = true; in.RangeFrom = "" },
	} {
		t.Run(name, func(t *testing.T) {
			in := validReleaseInput()
			mutate(&in)
			if _, err := BuildReleaseStatement(in); err == nil {
				t.Fatal("BuildReleaseStatement accepted an unbuildable input")
			}
		})
	}
}

// The emitter refuses to construct over schema bytes it cannot compile —
// mirroring the review emitter's construction-time posture.
func TestNewReleaseEmitterBadSchema(t *testing.T) {
	if _, err := NewReleaseEmitter(newEmitTestSigner(t), []byte("{")); err == nil {
		t.Fatal("NewReleaseEmitter accepted unparseable schema bytes")
	}
}
