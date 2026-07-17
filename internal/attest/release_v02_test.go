// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

func releaseV02SchemaBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vendorDir(t), "schemas", "release-v0.2.json"))
	if err != nil {
		t.Fatalf("reading release-v0.2 schema: %v", err)
	}
	return data
}

func hex64(c string) string { return strings.Repeat(c, 64) }

// validReleaseV02Input mirrors the vendored predicate-v0.2/release-valid fixture:
// a genesis (inception) advance producing a T2 prerelease of component auth.
// Digests are placeholder content-addresses — the builder records asserted
// facts, and no digest is derived here.
func validReleaseV02Input() ReleaseV02Input {
	commit := strings.Repeat("c", 40)
	iter := 1
	return ReleaseV02Input{
		TagName:   "auth/v0.1.0-t2.1",
		CommitSHA: commit,
		Repository: ReleaseV02Repository{
			ID:     "repo:semver-trust.test/auth",
			Origin: "https://example.test/auth.git",
			Digest: map[string]string{"sha256": hex64("a")},
		},
		Component: ReleaseComponent{Name: "auth", TagPrefix: "auth/"},
		Interval: ReleaseInterval{
			Mode:           "inception",
			To:             ReleaseObjectRef{ID: "commit:" + commit},
			SourceIdentity: map[string]string{"gitCommit": commit},
		},
		PolicyState: ReleasePolicyState{
			ActivePolicy: ReleaseDigestDescriptor{Path: ".semver-trust/policy.toml", Digest: map[string]string{"sha256": hex64("b")}},
			ActiveTrustRoots: []ReleaseDigestDescriptor{
				{Path: ".semver-trust/allowed_signers", Digest: map[string]string{"sha256": hex64("d")}},
			},
			CandidateTrustRoots: []ReleaseDigestDescriptor{},
			MandatoryWorkflows: []ReleaseDigestDescriptor{
				{Path: ".github/workflows/release.yml", Digest: map[string]string{"sha256": hex64("e")}},
			},
			Authority:         "bootstrap",
			AuthorityIdentity: ReleaseDigestDescriptor{URI: "bootstrap:auth", Digest: map[string]string{"sha256": hex64("f")}},
		},
		VersionState: ReleaseVersionState{
			Action:         "advance",
			Genesis:        true,
			ResultingState: ReleaseStateIdentity{ID: "version-state:auth:v0.1.0-t2.1", Digest: map[string]string{"sha256": hex64("1")}},
			TargetCore:     "0.1.0",
			TargetBump:     "minor",
			Emission: ReleaseTagEmission{
				Kind: "tag",
				Tag:  &ReleaseTagIdentity{Name: "auth/v0.1.0-t2.1", RawRefOID: strings.Repeat("2", 40), PeeledCommitOID: commit},
			},
			TargetLineage: []ReleaseObjectRef{{ID: "interval:auth:inception:1"}},
			Iteration:     &iter,
		},
		Trust: ReleaseTrust{Effective: "T2", Own: "T2", FloorSources: []ReleaseObjectRef{}},
		Provenance: []ReleaseProvenanceCommit{{
			SHA:   commit,
			Level: "T2",
			Authorship: ReleaseAuthorship{
				Class: "agent", Actor: "agent-ci", CredentialIdentity: "agent-ci@semver-trust.test",
				Trailers: map[string]string{"Provenance": "agent"},
			},
			Review:      ReleaseReviewRef{Class: "human", Actor: "alice", Attestation: &ReleaseObjectRef{ID: "review-attestation:1"}},
			Derivations: []ReleaseObjectRef{},
		}},
		Evidence: ReleaseEvidence{BlastRadius: ReleaseObjectRef{ID: "blast:moderate"}},
		Decision: ReleaseV02Decision{
			ClaimedBump: "minor", SemanticFloor: "minor", Threshold: "T2", Strategy: "demote", Channel: "prerelease",
		},
		Timestamp: emitEpoch,
	}
}

// An emitted release/v0.2 envelope must verify against an INDEPENDENT verifier
// enrolling the signing key for the attestation namespace — the same path
// verify takes — and yield the §8.1 continuity surface it was built from.
func TestEmitReleaseV02VerifiesIndependently(t *testing.T) {
	signer := newEmitTestSigner(t)
	emitter, err := NewReleaseV02Emitter(signer, releaseV02SchemaBytes(t))
	if err != nil {
		t.Fatalf("NewReleaseV02Emitter: %v", err)
	}

	in := validReleaseV02Input()
	emission, err := emitter.Emit(in)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if emission.KeyID != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Errorf("KeyID = %q, want the signer's SHA256 fingerprint", emission.KeyID)
	}

	verifier, err := NewVerifier([]sshsig.AllowedSigner{{
		Principals: []string{"releaser@semver-trust.test"},
		Namespaces: []string{Namespace},
		Key:        signer.PublicKey(),
	}}, map[string][]byte{PredicateReleaseV02: releaseV02SchemaBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := verifier.Verify(emission.Envelope, emitEpoch)
	if err != nil {
		t.Fatalf("independent Verify: %v", err)
	}
	if stmt.PredicateType != PredicateReleaseV02 {
		t.Errorf("predicateType = %q, want %q", stmt.PredicateType, PredicateReleaseV02)
	}
	if len(stmt.Subjects) != 1 || stmt.Subjects[0].Name != in.TagName || stmt.Subjects[0].Digest["gitCommit"] != in.CommitSHA {
		t.Errorf("subject = %+v, want tag name + gitCommit digest", stmt.Subjects)
	}

	// The payload round-trips the key continuity surface.
	var payload struct {
		Predicate struct {
			Profile struct {
				PredicateContract struct{ Name, Version string } `json:"predicate_contract"`
			} `json:"profile"`
			Interval     struct{ Mode string } `json:"interval"`
			PolicyState  struct{ Authority string } `json:"policy_state"`
			VersionState struct {
				Action         string `json:"action"`
				Genesis        bool   `json:"genesis"`
				TargetCore     string `json:"target_core"`
				ResultingState struct {
					Digest           map[string]string `json:"digest"`
					Canonicalization struct{ Name, Version string } `json:"canonicalization"`
				} `json:"resulting_state"`
			} `json:"version_state"`
			Decision struct {
				Threshold string `json:"threshold"`
				Channel   string `json:"channel"`
			} `json:"decision"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(emission.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	p := payload.Predicate
	if p.Profile.PredicateContract.Name != "release" || p.Profile.PredicateContract.Version != "0.2" {
		t.Errorf("predicate_contract = %+v, want release/0.2", p.Profile.PredicateContract)
	}
	if p.Interval.Mode != "inception" || p.PolicyState.Authority != "bootstrap" {
		t.Errorf("interval/authority = %s/%s, want inception/bootstrap", p.Interval.Mode, p.PolicyState.Authority)
	}
	if p.VersionState.Action != "advance" || !p.VersionState.Genesis || p.VersionState.TargetCore != "0.1.0" {
		t.Errorf("version_state = %+v, want advance/genesis/0.1.0", p.VersionState)
	}
	if p.VersionState.ResultingState.Canonicalization.Name != "semver-trust-version-state-json" ||
		p.VersionState.ResultingState.Canonicalization.Version != "0.2" {
		t.Errorf("resulting_state canonicalization = %+v, want the ADR-036 profile", p.VersionState.ResultingState.Canonicalization)
	}
	if p.Decision.Threshold != "T2" || p.Decision.Channel != "prerelease" {
		t.Errorf("decision = %+v, want threshold T2 / prerelease", p.Decision)
	}
}

// The emitted payload validates against the vendored release-v0.2 schema through
// the same ValidatePayload path verify uses.
func TestEmitReleaseV02ValidatesAgainstVendoredSchema(t *testing.T) {
	payload, err := BuildReleaseV02Statement(validReleaseV02Input())
	if err != nil {
		t.Fatalf("BuildReleaseV02Statement: %v", err)
	}
	verifier, err := NewVerifier(nil, map[string][]byte{PredicateReleaseV02: releaseV02SchemaBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.ValidatePayload(payload); err != nil {
		t.Errorf("ValidatePayload against vendored release-v0.2 schema: %v", err)
	}
}

// Required-nullable wire fields (prior_state, predecessor, adoption_boundary,
// compatibility/coverage, supersedes, pending_corrective_floor) emit as explicit
// JSON null at genesis, not omitted — the schema's oneOf(null, …) shape.
func TestEmitReleaseV02GenesisNullableFieldsEmitNull(t *testing.T) {
	payload, err := BuildReleaseV02Statement(validReleaseV02Input())
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Predicate struct {
			Interval     map[string]json.RawMessage `json:"interval"`
			VersionState map[string]json.RawMessage `json:"version_state"`
			Evidence     map[string]json.RawMessage `json:"evidence"`
			Decision     map[string]json.RawMessage `json:"decision"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		block map[string]json.RawMessage
		field string
	}{
		{raw.Predicate.Interval, "adoption_boundary"},
		{raw.Predicate.Interval, "predecessor_attestation"},
		{raw.Predicate.VersionState, "predecessor"},
		{raw.Predicate.VersionState, "prior_state"},
		{raw.Predicate.VersionState, "pending_corrective_floor"},
		{raw.Predicate.Evidence, "compatibility"},
		{raw.Predicate.Evidence, "coverage"},
		{raw.Predicate.Decision, "supersedes"},
	}
	for _, c := range checks {
		v, present := c.block[c.field]
		if !present {
			t.Errorf("%s absent, want explicit JSON null", c.field)
			continue
		}
		if string(v) != "null" {
			t.Errorf("%s = %s, want JSON null", c.field, v)
		}
	}
}

func TestBuildReleaseV02Preconditions(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*ReleaseV02Input)
		wantSub string
	}{
		{"no tag", func(in *ReleaseV02Input) { in.TagName = "" }, "subject tag name and commit"},
		{"no commit", func(in *ReleaseV02Input) { in.CommitSHA = "" }, "subject tag name and commit"},
		{"no provenance", func(in *ReleaseV02Input) { in.Provenance = nil }, "at least one provenance"},
		{"zero timestamp", func(in *ReleaseV02Input) { in.Timestamp = time.Time{} }, "injected timestamp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := validReleaseV02Input()
			c.mutate(&in)
			if _, err := BuildReleaseV02Statement(in); err == nil {
				t.Fatalf("expected an error for %s", c.name)
			} else if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("error = %v, want substring %q", err, c.wantSub)
			}
		})
	}
}
