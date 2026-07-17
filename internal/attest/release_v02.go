// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

// This file is the emission half for the release/v0.2 predicate (ADR-030, §8.1):
// the successor to release/v0.1, a structural rewrite carrying the full v0.10
// continuity surface — the exact interval, the digest-pinned policy state, the
// authenticated version state (with its ADR-036 canonicalized identities), the
// trust/provenance/evidence vectors, and the threshold-bearing decision. It
// reuses the emit.go core verbatim: the payload is schema-validated against
// release-v0.2.json BEFORE signing (signed bytes are frozen), and the finished
// envelope is run back through the real Verifier before it is output. No wall
// clock is read here (ADR-018): the timestamp and verification instant are
// injected by the caller.
//
// The builder only shapes bytes. Every value — including the version-state
// identity digests (computed by the caller via version.StateDigest) and the
// emitted tag's raw/peeled OIDs — is supplied by the caller; internal/attest
// stays uncoupled from the version canonicalization and the git layer.

// versionStateCanonicalizationProfile is the fixed ADR-036 profile every v0.2
// version-state identity binds. It is a constant (not a caller input) because
// v0.2 pins exactly one canonicalization; a future profile version would be a
// new predicate.
var versionStateCanonicalizationProfile = profileJSON{
	Name:    "semver-trust-version-state-json",
	Version: "0.2",
}

// ReleaseV02Repository is the §4.3/ADR-030 canonical repository identity.
type ReleaseV02Repository struct {
	ID     string
	Origin string // optional
	Digest map[string]string
}

// ReleaseComponent is the released unit's §5.1 scope name and §7.1 tag prefix.
type ReleaseComponent struct {
	Name      string
	TagPrefix string // may be empty
}

// ReleaseObjectRef is a §8.1 object identity — an id (e.g. "commit:<sha>",
// "blast:moderate") with an optional digest set.
type ReleaseObjectRef struct {
	ID     string
	Digest map[string]string // optional
}

// ReleaseDigestDescriptor is a policy-state digest descriptor: an optional
// uri/path and a required digest set (the pinned bytes of a policy or trust
// registry).
type ReleaseDigestDescriptor struct {
	URI    string // optional
	Path   string // optional
	Digest map[string]string
}

// ReleaseTagIdentity is a §7.5 immutable tag binding: the canonical tag name and
// its raw Git ref-target and peeled commit object IDs (so a moved/recreated ref
// is detected).
type ReleaseTagIdentity struct {
	Name            string
	RawRefOID       string
	PeeledCommitOID string
}

// ReleaseStateIdentity is a §7.5/ADR-036 version-state identity: a stable id and
// the canonicalization digest (bare-hex digest set, e.g. {"sha256": …}). The
// canonicalization profile is fixed (ADR-036) and filled by the builder.
type ReleaseStateIdentity struct {
	ID     string
	Digest map[string]string
}

// ReleaseInterval is the §5.2/ADR-027 interval the release evaluated.
type ReleaseInterval struct {
	Mode                   string // inception | adoption | recurring
	To                     ReleaseObjectRef
	AdoptionBoundary       *ReleaseObjectRef // null unless adoption
	PredecessorAttestation *ReleaseObjectRef // null unless recurring
	SourceIdentity         map[string]string
}

// ReleasePolicyState is the §5.4/ADR-028 authenticated policy state.
type ReleasePolicyState struct {
	ActivePolicy        ReleaseDigestDescriptor
	ActiveTrustRoots    []ReleaseDigestDescriptor
	CandidatePolicy     *ReleaseDigestDescriptor // null when candidate == active (genesis)
	CandidateTrustRoots []ReleaseDigestDescriptor
	MandatoryWorkflows  []ReleaseDigestDescriptor
	Authority           string // bootstrap | predecessor
	AuthorityIdentity   ReleaseDigestDescriptor
}

// ReleaseTagEmission is the §7.5 exact-tag emission or an explicit no-emission
// marker. Tag is null for kind "none" or a preview (dry-run).
type ReleaseTagEmission struct {
	Kind string // tag | none
	Tag  *ReleaseTagIdentity
}

// ReleaseVersionState is the §7.5/ADR-029 authenticated version state.
type ReleaseVersionState struct {
	Action                 string // advance | recut | supersede
	Genesis                bool
	Predecessor            *ReleaseTagIdentity   // null at new-line genesis
	PriorState             *ReleaseStateIdentity // null at genesis
	ResultingState         ReleaseStateIdentity
	TargetCore             string
	TargetBump             string
	Emission               ReleaseTagEmission
	TargetLineage          []ReleaseObjectRef
	Iteration              *int    // null/absent for a clean cut
	PendingCorrectiveFloor *string // null unless a carried under-bump correction
}

// ReleaseTrust is the §5.2/§5.3 trust result.
type ReleaseTrust struct {
	Effective    string
	Own          string
	FloorSources []ReleaseObjectRef
}

// ReleaseAuthorship is a provenance commit's §3.2/§4.1 authorship facts.
type ReleaseAuthorship struct {
	Class              string // human | agent | mixed | ambiguous
	Actor              string // optional
	CredentialIdentity string // optional (the verified signer principal)
	Trailers           map[string]string
}

// ReleaseReviewRef is a provenance commit's §4.3 review facts.
type ReleaseReviewRef struct {
	Class       string // human | agent | none
	Actor       string
	Attestation *ReleaseObjectRef
}

// ReleaseProvenanceCommit is one §8.1 provenance row.
type ReleaseProvenanceCommit struct {
	SHA         string
	Level       string
	Authorship  ReleaseAuthorship
	Review      ReleaseReviewRef
	Derivations []ReleaseObjectRef
}

// ReleaseEvidence is the §6 evidence vector as object-identity references.
type ReleaseEvidence struct {
	Compatibility *ReleaseObjectRef // null when no differ ran
	BlastRadius   ReleaseObjectRef
	Coverage      *ReleaseObjectRef // null when no coverage provider ran
}

// ReleaseV02Decision is the §6.3/§6.4 decision block (threshold-bearing, ADR-032).
type ReleaseV02Decision struct {
	ClaimedBump   string
	SemanticFloor string
	Threshold     string
	Strategy      string
	Channel       string
	Supersedes    *ReleaseObjectRef
}

// ReleaseV02Input is everything a §8.1 release/v0.2 statement is built from. The
// boilerplate profile block is defaulted; the caller supplies every release
// fact. The timestamp is injected (ADR-018).
type ReleaseV02Input struct {
	// TagName is the emitted §7.1 tag (the subject name); CommitSHA is the
	// release target (TO), bound as the subject's gitCommit digest.
	TagName   string
	CommitSHA string

	Repository   ReleaseV02Repository
	Component    ReleaseComponent
	Interval     ReleaseInterval
	PolicyState  ReleasePolicyState
	VersionState ReleaseVersionState
	Trust        ReleaseTrust
	Provenance   []ReleaseProvenanceCommit
	Evidence     ReleaseEvidence
	Decision     ReleaseV02Decision

	Timestamp           time.Time
	VerificationInstant time.Time // defaults to Timestamp when zero
	Extensions          map[string]any
}

// Wire shapes. Field order = payload byte order (encoding/json marshals in
// declaration order); the signed bytes are frozen at Sign. The default profile
// is fixed (no runtime build info), so the same input always produces the same
// bytes (ADR-018).
type releaseV02StatementJSON struct {
	Type          string                  `json:"_type"`
	Subject       []Subject               `json:"subject"`
	PredicateType string                  `json:"predicateType"`
	Predicate     releaseV02PredicateJSON `json:"predicate"`
}

type releaseV02PredicateJSON struct {
	Profile      releaseProfileJSON     `json:"profile"`
	Repository   repositoryIdentityJSON `json:"repository"`
	Component    componentJSON          `json:"component"`
	Interval     releaseIntervalJSON    `json:"interval"`
	PolicyState  policyStateJSON        `json:"policy_state"`
	VersionState versionStateJSON       `json:"version_state"`
	Trust        trustResultJSON        `json:"trust"`
	Provenance   []provenanceCommitJSON `json:"provenance"`
	Evidence     evidenceVectorJSON     `json:"evidence"`
	Decision     releaseV02DecisionJSON    `json:"decision"`
	Timestamp    string                 `json:"timestamp"`
	Extensions   map[string]any         `json:"extensions,omitempty"`
}

type releaseProfileJSON struct {
	Specification       profileJSON `json:"specification"`
	PredicateContract   profileJSON `json:"predicate_contract"`
	Evaluator           profileJSON `json:"evaluator"`
	RepositoryIdentity  profileJSON `json:"repository_identity"`
	Graph               profileJSON `json:"graph"`
	Policy              profileJSON `json:"policy"`
	VerificationTime    profileJSON `json:"verification_time"`
	VerificationInstant string      `json:"verification_instant"`
}

type componentJSON struct {
	Name      string `json:"name"`
	TagPrefix string `json:"tag_prefix"`
}

type digestDescriptorJSON struct {
	URI    string            `json:"uri,omitempty"`
	Path   string            `json:"path,omitempty"`
	Digest map[string]string `json:"digest"`
}

type tagIdentityJSON struct {
	Name            string `json:"name"`
	RawRefOID       string `json:"raw_ref_oid"`
	PeeledCommitOID string `json:"peeled_commit_oid"`
}

type stateIdentityJSON struct {
	ID               string            `json:"id"`
	Digest           map[string]string `json:"digest"`
	Canonicalization profileJSON       `json:"canonicalization"`
}

type releaseIntervalJSON struct {
	Mode                   string              `json:"mode"`
	To                     objectIdentityJSON  `json:"to"`
	AdoptionBoundary       *objectIdentityJSON `json:"adoption_boundary"`
	PredecessorAttestation *objectIdentityJSON `json:"predecessor_attestation"`
	SourceIdentity         map[string]string   `json:"source_identity"`
}

type policyStateJSON struct {
	ActivePolicy        digestDescriptorJSON   `json:"active_policy"`
	ActiveTrustRoots    []digestDescriptorJSON `json:"active_trust_roots"`
	CandidatePolicy     *digestDescriptorJSON  `json:"candidate_policy"`
	CandidateTrustRoots []digestDescriptorJSON `json:"candidate_trust_roots"`
	MandatoryWorkflows  []digestDescriptorJSON `json:"mandatory_workflows"`
	Authority           string                 `json:"authority"`
	AuthorityIdentity   digestDescriptorJSON   `json:"authority_identity"`
}

type versionStateJSON struct {
	Action                 string               `json:"action"`
	Genesis                bool                 `json:"genesis"`
	Predecessor            *tagIdentityJSON     `json:"predecessor"`
	PriorState             *stateIdentityJSON   `json:"prior_state"`
	ResultingState         stateIdentityJSON    `json:"resulting_state"`
	TargetCore             string               `json:"target_core"`
	TargetBump             string               `json:"target_bump"`
	Emission               tagEmissionJSON      `json:"emission"`
	TargetLineage          []objectIdentityJSON `json:"target_lineage"`
	Iteration              *int                 `json:"iteration,omitempty"`
	PendingCorrectiveFloor *string              `json:"pending_corrective_floor"`
}

type tagEmissionJSON struct {
	Kind string           `json:"kind"`
	Tag  *tagIdentityJSON `json:"tag"`
}

type trustResultJSON struct {
	Effective    string               `json:"effective"`
	Own          string               `json:"own"`
	FloorSources []objectIdentityJSON `json:"floor_sources"`
}

type provenanceCommitJSON struct {
	SHA         string               `json:"sha"`
	Level       string               `json:"level"`
	Authorship  authorshipJSON       `json:"authorship"`
	Review      reviewRefJSON        `json:"review"`
	Derivations []objectIdentityJSON `json:"derivations,omitempty"`
}

type authorshipJSON struct {
	Class              string            `json:"class"`
	Actor              string            `json:"actor,omitempty"`
	CredentialIdentity string            `json:"credential_identity,omitempty"`
	Trailers           map[string]string `json:"trailers,omitempty"`
}

type reviewRefJSON struct {
	Class       string              `json:"class"`
	Actor       string              `json:"actor,omitempty"`
	Attestation *objectIdentityJSON `json:"attestation,omitempty"`
}

type evidenceVectorJSON struct {
	Compatibility *objectIdentityJSON `json:"compatibility"`
	BlastRadius   objectIdentityJSON  `json:"blast_radius"`
	Coverage      *objectIdentityJSON `json:"coverage"`
}

type releaseV02DecisionJSON struct {
	ClaimedBump   string              `json:"claimed_bump"`
	SemanticFloor string              `json:"semantic_floor"`
	Threshold     string              `json:"threshold"`
	Strategy      string              `json:"strategy"`
	Channel       string              `json:"channel"`
	Supersedes    *objectIdentityJSON `json:"supersedes"`
}

// defaultReleaseProfile is the fixed profile block the emitter declares. The
// values are constants, not runtime build info (ADR-018 reproducibility), and no
// verifier consumes the release profile identity strings (they are conformance
// declarations, schema-validated for structure only). instant is the injected
// verification instant.
func defaultReleaseProfile(instant time.Time) releaseProfileJSON {
	return releaseProfileJSON{
		Specification:       profileJSON{Name: "semver-trust", Version: "0.10"},
		PredicateContract:   profileJSON{Name: "release", Version: "0.2"},
		Evaluator:           profileJSON{Name: "semver-trust-go", Version: "0.10"},
		RepositoryIdentity:  profileJSON{Name: "git", Version: "0.1"},
		Graph:               profileJSON{Name: "workspace-graph", Version: "0.1"},
		Policy:              profileJSON{Name: "semver-trust-policy", Version: "0.1"},
		VerificationTime:    profileJSON{Name: "injected-clock", Version: "0.1"},
		VerificationInstant: instant.UTC().Format(time.RFC3339),
	}
}

func objRef(r ReleaseObjectRef) objectIdentityJSON {
	return objectIdentityJSON(r)
}

func objRefPtr(r *ReleaseObjectRef) *objectIdentityJSON {
	if r == nil {
		return nil
	}
	v := objRef(*r)
	return &v
}

func objRefs(rs []ReleaseObjectRef) []objectIdentityJSON {
	out := make([]objectIdentityJSON, 0, len(rs))
	for _, r := range rs {
		out = append(out, objRef(r))
	}
	return out
}

func digestDesc(d ReleaseDigestDescriptor) digestDescriptorJSON {
	return digestDescriptorJSON(d)
}

func digestDescPtr(d *ReleaseDigestDescriptor) *digestDescriptorJSON {
	if d == nil {
		return nil
	}
	v := digestDesc(*d)
	return &v
}

func digestDescs(ds []ReleaseDigestDescriptor) []digestDescriptorJSON {
	out := make([]digestDescriptorJSON, 0, len(ds))
	for _, d := range ds {
		out = append(out, digestDesc(d))
	}
	return out
}

func tagID(t ReleaseTagIdentity) tagIdentityJSON {
	return tagIdentityJSON(t)
}

func tagIDPtr(t *ReleaseTagIdentity) *tagIdentityJSON {
	if t == nil {
		return nil
	}
	v := tagID(*t)
	return &v
}

func stateID(s ReleaseStateIdentity) stateIdentityJSON {
	return stateIdentityJSON{
		ID:               s.ID,
		Digest:           s.Digest,
		Canonicalization: versionStateCanonicalizationProfile,
	}
}

func stateIDPtr(s *ReleaseStateIdentity) *stateIdentityJSON {
	if s == nil {
		return nil
	}
	v := stateID(*s)
	return &v
}

// BuildReleaseV02Statement builds the serialized §8.1 in-toto Statement for a
// release/v0.2 predicate. It only shapes bytes — schema validation happens in
// Emit, before any signing. The "at least one" preconditions are checked here
// for a friendly error; every other structural rule (required digests, enums,
// core pattern) is enforced by the schema at emit time.
func BuildReleaseV02Statement(in ReleaseV02Input) ([]byte, error) {
	if in.TagName == "" || in.CommitSHA == "" {
		return nil, errors.New("attest: release/v0.2 statement needs a subject tag name and commit SHA")
	}
	if len(in.Provenance) == 0 {
		return nil, errors.New("attest: release/v0.2 statement needs at least one provenance commit")
	}
	if in.Timestamp.IsZero() {
		return nil, errors.New("attest: release/v0.2 statement needs an injected timestamp (ADR-018: no wall clock here)")
	}

	instant := in.VerificationInstant
	if instant.IsZero() {
		instant = in.Timestamp
	}

	provenance := make([]provenanceCommitJSON, 0, len(in.Provenance))
	for _, c := range in.Provenance {
		provenance = append(provenance, provenanceCommitJSON{
			SHA:   c.SHA,
			Level: c.Level,
			Authorship: authorshipJSON{
				Class:              c.Authorship.Class,
				Actor:              c.Authorship.Actor,
				CredentialIdentity: c.Authorship.CredentialIdentity,
				Trailers:           c.Authorship.Trailers,
			},
			Review: reviewRefJSON{
				Class:       c.Review.Class,
				Actor:       c.Review.Actor,
				Attestation: objRefPtr(c.Review.Attestation),
			},
			Derivations: objRefs(c.Derivations),
		})
	}

	vs := in.VersionState
	statement := releaseV02StatementJSON{
		Type:          StatementType,
		Subject:       []Subject{{Name: in.TagName, Digest: map[string]string{"gitCommit": in.CommitSHA}}},
		PredicateType: PredicateReleaseV02,
		Predicate: releaseV02PredicateJSON{
			Profile: defaultReleaseProfile(instant),
			Repository: repositoryIdentityJSON{
				ID:     in.Repository.ID,
				Origin: in.Repository.Origin,
				Digest: in.Repository.Digest,
			},
			Component: componentJSON{Name: in.Component.Name, TagPrefix: in.Component.TagPrefix},
			Interval: releaseIntervalJSON{
				Mode:                   in.Interval.Mode,
				To:                     objRef(in.Interval.To),
				AdoptionBoundary:       objRefPtr(in.Interval.AdoptionBoundary),
				PredecessorAttestation: objRefPtr(in.Interval.PredecessorAttestation),
				SourceIdentity:         in.Interval.SourceIdentity,
			},
			PolicyState: policyStateJSON{
				ActivePolicy:        digestDesc(in.PolicyState.ActivePolicy),
				ActiveTrustRoots:    digestDescs(in.PolicyState.ActiveTrustRoots),
				CandidatePolicy:     digestDescPtr(in.PolicyState.CandidatePolicy),
				CandidateTrustRoots: digestDescs(in.PolicyState.CandidateTrustRoots),
				MandatoryWorkflows:  digestDescs(in.PolicyState.MandatoryWorkflows),
				Authority:           in.PolicyState.Authority,
				AuthorityIdentity:   digestDesc(in.PolicyState.AuthorityIdentity),
			},
			VersionState: versionStateJSON{
				Action:                 vs.Action,
				Genesis:                vs.Genesis,
				Predecessor:            tagIDPtr(vs.Predecessor),
				PriorState:             stateIDPtr(vs.PriorState),
				ResultingState:         stateID(vs.ResultingState),
				TargetCore:             vs.TargetCore,
				TargetBump:             vs.TargetBump,
				Emission:               tagEmissionJSON{Kind: vs.Emission.Kind, Tag: tagIDPtr(vs.Emission.Tag)},
				TargetLineage:          objRefs(vs.TargetLineage),
				Iteration:              vs.Iteration,
				PendingCorrectiveFloor: vs.PendingCorrectiveFloor,
			},
			Trust: trustResultJSON{
				Effective:    in.Trust.Effective,
				Own:          in.Trust.Own,
				FloorSources: objRefs(in.Trust.FloorSources),
			},
			Provenance: provenance,
			Evidence: evidenceVectorJSON{
				Compatibility: objRefPtr(in.Evidence.Compatibility),
				BlastRadius:   objRef(in.Evidence.BlastRadius),
				Coverage:      objRefPtr(in.Evidence.Coverage),
			},
			Decision: releaseV02DecisionJSON{
				ClaimedBump:   in.Decision.ClaimedBump,
				SemanticFloor: in.Decision.SemanticFloor,
				Threshold:     in.Decision.Threshold,
				Strategy:      in.Decision.Strategy,
				Channel:       in.Decision.Channel,
				Supersedes:    objRefPtr(in.Decision.Supersedes),
			},
			Timestamp:  in.Timestamp.UTC().Format(time.RFC3339),
			Extensions: in.Extensions,
		},
	}
	return json.Marshal(statement)
}

// ReleaseV02Emitter signs release/v0.2 statements into DSSE envelopes per
// ADR-022, through the same core as review/v0.2 and release/v0.1: the payload is
// schema-validated against release-v0.2.json BEFORE signing, and the finished
// envelope is verified before it is output.
type ReleaseV02Emitter struct {
	core *emitter
}

// NewReleaseV02Emitter builds an emitter from a signer and the raw release-v0.2
// JSON Schema bytes (injected, like every other piece of trust material — the
// CLI wires the vendored conformance copy).
func NewReleaseV02Emitter(signer ssh.Signer, releaseSchema []byte) (*ReleaseV02Emitter, error) {
	core, err := newEmitter(signer, PredicateReleaseV02, releaseSchema)
	if err != nil {
		return nil, err
	}
	return &ReleaseV02Emitter{core: core}, nil
}

// Emit builds, validates, signs, and self-verifies a release/v0.2 attestation —
// the emit.go riders, applied to the §8.1 successor predicate.
func (e *ReleaseV02Emitter) Emit(in ReleaseV02Input) (Emission, error) {
	payload, err := BuildReleaseV02Statement(in)
	if err != nil {
		return Emission{}, err
	}
	return e.core.emit(payload, in.Timestamp)
}

// Signer returns the emitter's signing-key fingerprint — the untrusted keyid
// hint its envelopes carry (ADR-022).
func (e *ReleaseV02Emitter) Signer() string {
	return ssh.FingerprintSHA256(e.core.signer.PublicKey())
}
