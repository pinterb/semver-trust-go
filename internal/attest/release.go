// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

// This file is the release half of emission: it builds §8.1 release
// statements and signs them into ADR-022 DSSE envelopes through the same
// shared core as reviews (emit.go) — schema-validate BEFORE signing,
// emit-then-verify through the real Verifier, never emit blind.

// ComponentVersion pins a first-party component to a version or tree state
// (§5.3) — the floor-source and dependencies_pinned shape of the predicate.
type ComponentVersion struct {
	Component string
	Version   string
}

// ReleaseCommit is one row of the §8.1 provenance vector: the per-commit
// authorship and review classes MUST be preserved even though the tag
// carries only the scalar level (§3.2).
type ReleaseCommit struct {
	SHA   string
	Level string // "T0".."T3"

	AuthorshipClass string // "human" | "agent" | "mixed" | "ambiguous"
	SignerIdentity  string // verified signer identity (advisory here)
	// Trailers are the commit's self-asserted provenance trailers (§4.1),
	// advisory by definition.
	Trailers map[string]string

	ReviewClass string // "human" | "agent" | "none"
	// ReviewerIdentity is the verified reviewer identity when a review was
	// consumed.
	ReviewerIdentity string
	// ReviewAttestation references the covering review attestation that was
	// cryptographically consumed (§4.3, §8.2), empty when none was.
	ReviewAttestation string

	// Derivations names the §4.4 rules whose verified reproducibility
	// re-levelled paths in this commit.
	Derivations []string
}

// ReleaseCompat is the compatibility-differ evidence feeding the semantic
// floor (§6.1). It exists only when a differ actually ran — absence, never
// fabrication (§1.1, P4).
type ReleaseCompat struct {
	Provider string // e.g. "apidiff"
	Result   string // e.g. "compatible" | "additive" | "breaking"
}

// ReleaseBlast is the §6.2 blast radius: the qualitative score and the full
// input set that produced it MUST appear in the attestation. Optional
// numeric inputs are pointers so absence is representable (honest
// degradation) without fabricating zeros.
type ReleaseBlast struct {
	LOC   *int
	Files *int
	FanIn string // "" when no provider supplied it
	Score string // "low" | "moderate" | "high"
	// Inputs is the open §6.2 extension point: every blast input and its
	// source, e.g. {"source": "operator", "changed_files": 12}.
	Inputs map[string]any
}

// ReleaseDecision is the §6.3/§6.4 decision block. The policy digest pins
// the exact policy that produced the decision so it is reproducible (§8.1).
type ReleaseDecision struct {
	ClaimedBump   string // "patch" | "minor" | "major"
	SemanticFloor string
	Strategy      string // "demote" | "inflate"
	Channel       string // "clean" | "prerelease"
	PolicyPath    string
	PolicyDigest  string // "alg:value" form, e.g. "sha256:<hex>"
	// Supersedes references the attestation this one supersedes (§7.3);
	// empty means an original decision and is emitted as null.
	Supersedes string
}

// ReleaseInput is everything a §8.1 release statement is built from — the
// verify report's provenance vector plus the step-8 decision. The timestamp
// is injected (ADR-018): callers read the clock at the process boundary,
// never here.
type ReleaseInput struct {
	// Tag is the §7.1 tag name the subject binds to CommitSHA.
	Tag string
	// CommitSHA is the release target commit (TO).
	CommitSHA string
	// Component is the releasable unit's scope name (§2, §5.1).
	Component string

	// RangeFrom is the previous tag or the adoption boundary; empty means a
	// first release from the repository root and is emitted as null (§5.2).
	RangeFrom string
	// FromIsAdoptionBoundary discloses that RangeFrom is the policy-pinned
	// adoption boundary (ADR-026): "verified since the boundary" is a
	// different claim from "verified since inception".
	FromIsAdoptionBoundary bool

	// Effective and Own are the propagated and per-scope trust levels
	// (§5.2, §5.3).
	Effective string
	Own       string
	// FloorSource is the internal dependency that floored effective trust,
	// nil when the component floors itself (emitted as null — the schema's
	// documented meaning, §5.3).
	FloorSource *ComponentVersion
	// DependenciesPinned lists the internal dependency states effective
	// trust was computed against; empty (never absent) for a component with
	// no internal deps.
	DependenciesPinned []ComponentVersion

	// Commits is the full §8.1 provenance vector, at least one row.
	Commits []ReleaseCommit

	// Compat is the differ evidence, nil when no differ ran (§6.1).
	Compat *ReleaseCompat
	// CoverageChangedLines is the changed-line coverage fraction, nil when
	// no coverage provider ran (§6.2).
	CoverageChangedLines *float64
	// Blast is the §6.2 blast radius (required).
	Blast ReleaseBlast

	// Decision is the §6.3/§6.4 decision block.
	Decision ReleaseDecision

	// Timestamp is the decision instant, injected by the caller.
	Timestamp time.Time
}

// The wire shapes of the release statement. Field order here is the
// payload's byte order: encoding/json marshals struct fields in declaration
// order, so the serialized statement is stable across runs — which matters,
// because the signed bytes are frozen the moment Sign covers them.
type releaseStatementJSON struct {
	Type          string               `json:"_type"`
	Subject       []Subject            `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     releasePredicateJSON `json:"predicate"`
}

type releasePredicateJSON struct {
	Component string               `json:"component"`
	Range     releaseRangeJSON     `json:"range"`
	Trust     releaseTrustJSON     `json:"trust"`
	Commits   []releaseCommitJSON  `json:"commits"`
	Evidence  releaseEvidenceJSON  `json:"evidence"`
	Decision  releaseDecisionJSON  `json:"decision"`
	Timestamp string               `json:"timestamp"`
}

type releaseRangeJSON struct {
	From *string `json:"from"` // present-and-null for a first release
	To   string  `json:"to"`
	// FromIsAdoptionBoundary is the ADR-026 disclosure marker, additive
	// within v0.1 and omitted when false.
	FromIsAdoptionBoundary bool `json:"from_is_adoption_boundary,omitempty"`
}

type releaseTrustJSON struct {
	Effective          string                  `json:"effective"`
	Own                string                  `json:"own"`
	FloorSource        *componentVersionJSON   `json:"floor_source"` // null when self-floored
	DependenciesPinned []componentVersionJSON  `json:"dependencies_pinned"`
}

type componentVersionJSON struct {
	Component string `json:"component"`
	Version   string `json:"version"`
}

type releaseCommitJSON struct {
	SHA         string                `json:"sha"`
	Level       string                `json:"level"`
	Authorship  releaseAuthorshipJSON `json:"authorship"`
	Review      releaseReviewJSON     `json:"review"`
	Derivations []releaseDerivJSON    `json:"derivations"`
}

type releaseAuthorshipJSON struct {
	Class    string            `json:"class"`
	Identity string            `json:"identity,omitempty"`
	Trailers map[string]string `json:"trailers,omitempty"`
}

type releaseReviewJSON struct {
	Class       string `json:"class"`
	Identity    string `json:"identity,omitempty"`
	Attestation string `json:"attestation,omitempty"`
}

type releaseDerivJSON struct {
	Name string `json:"name"`
}

type releaseEvidenceJSON struct {
	Compat               *releaseCompatJSON `json:"compat,omitempty"`
	CoverageChangedLines *float64           `json:"coverage_changed_lines,omitempty"`
	BlastRadius          releaseBlastJSON   `json:"blast_radius"`
}

type releaseCompatJSON struct {
	Provider string `json:"provider"`
	Result   string `json:"result"`
}

type releaseBlastJSON struct {
	LOC    *int           `json:"loc,omitempty"`
	Files  *int           `json:"files,omitempty"`
	FanIn  string         `json:"fan_in,omitempty"`
	Score  string         `json:"score"`
	Inputs map[string]any `json:"inputs"`
}

type releaseDecisionJSON struct {
	ClaimedBump   string            `json:"claimed_bump"`
	SemanticFloor string            `json:"semantic_floor"`
	Strategy      string            `json:"strategy"`
	Channel       string            `json:"channel"`
	Policy        releasePolicyJSON `json:"policy"`
	Supersedes    *string           `json:"supersedes"` // present-and-null when original
}

type releasePolicyJSON struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// BuildReleaseStatement builds the serialized §8.1 in-toto Statement for a
// release: the subject binds the tag name to the release commit SHA, the
// predicate type is the frozen PredicateRelease URI, and the timestamp is
// the injected instant in RFC 3339 UTC. It only shapes bytes — schema
// validation happens in Emit, before any signing.
func BuildReleaseStatement(in ReleaseInput) ([]byte, error) {
	switch {
	case in.Tag == "":
		return nil, errors.New("attest: release statement needs the tag name")
	case in.CommitSHA == "":
		return nil, errors.New("attest: release statement needs the release commit SHA")
	case in.Component == "":
		return nil, errors.New("attest: release statement needs the component scope name (§5.1)")
	case len(in.Commits) == 0:
		return nil, errors.New("attest: release statement needs at least one provenance-vector commit (§8.1)")
	case in.Timestamp.IsZero():
		return nil, errors.New("attest: release statement needs an injected timestamp (ADR-018: no wall clock here)")
	}

	var from *string
	if in.RangeFrom != "" {
		from = &in.RangeFrom
	}
	if in.FromIsAdoptionBoundary && from == nil {
		return nil, errors.New("attest: from_is_adoption_boundary requires the boundary in range.from (ADR-026 disclosure)")
	}

	var floorSource *componentVersionJSON
	if in.FloorSource != nil {
		floorSource = &componentVersionJSON{Component: in.FloorSource.Component, Version: in.FloorSource.Version}
	}
	pinned := make([]componentVersionJSON, 0, len(in.DependenciesPinned))
	for _, d := range in.DependenciesPinned {
		pinned = append(pinned, componentVersionJSON(d))
	}

	commits := make([]releaseCommitJSON, 0, len(in.Commits))
	for _, c := range in.Commits {
		derivations := make([]releaseDerivJSON, 0, len(c.Derivations))
		for _, name := range c.Derivations {
			derivations = append(derivations, releaseDerivJSON{Name: name})
		}
		commits = append(commits, releaseCommitJSON{
			SHA:   c.SHA,
			Level: c.Level,
			Authorship: releaseAuthorshipJSON{
				Class:    c.AuthorshipClass,
				Identity: c.SignerIdentity,
				Trailers: c.Trailers,
			},
			Review: releaseReviewJSON{
				Class:       c.ReviewClass,
				Identity:    c.ReviewerIdentity,
				Attestation: c.ReviewAttestation,
			},
			Derivations: derivations,
		})
	}

	var compat *releaseCompatJSON
	if in.Compat != nil {
		compat = &releaseCompatJSON{Provider: in.Compat.Provider, Result: in.Compat.Result}
	}
	inputs := in.Blast.Inputs
	if inputs == nil {
		inputs = map[string]any{}
	}

	var supersedes *string
	if in.Decision.Supersedes != "" {
		supersedes = &in.Decision.Supersedes
	}

	return json.Marshal(releaseStatementJSON{
		Type:          StatementType,
		Subject:       []Subject{{Name: in.Tag, Digest: map[string]string{"gitCommit": in.CommitSHA}}},
		PredicateType: PredicateRelease,
		Predicate: releasePredicateJSON{
			Component: in.Component,
			Range: releaseRangeJSON{
				From:                   from,
				To:                     in.CommitSHA,
				FromIsAdoptionBoundary: in.FromIsAdoptionBoundary,
			},
			Trust: releaseTrustJSON{
				Effective:          in.Effective,
				Own:                in.Own,
				FloorSource:        floorSource,
				DependenciesPinned: pinned,
			},
			Commits: commits,
			Evidence: releaseEvidenceJSON{
				Compat:               compat,
				CoverageChangedLines: in.CoverageChangedLines,
				BlastRadius: releaseBlastJSON{
					LOC:    in.Blast.LOC,
					Files:  in.Blast.Files,
					FanIn:  in.Blast.FanIn,
					Score:  in.Blast.Score,
					Inputs: inputs,
				},
			},
			Decision: releaseDecisionJSON{
				ClaimedBump:   in.Decision.ClaimedBump,
				SemanticFloor: in.Decision.SemanticFloor,
				Strategy:      in.Decision.Strategy,
				Channel:       in.Decision.Channel,
				Policy:        releasePolicyJSON{Path: in.Decision.PolicyPath, Digest: in.Decision.PolicyDigest},
				Supersedes:    supersedes,
			},
			Timestamp: in.Timestamp.UTC().Format(time.RFC3339),
		},
	})
}

// ReleaseEmitter signs release statements into DSSE envelopes per ADR-022,
// through the same core as reviews: the payload is schema-validated against
// release-v0.1.json BEFORE signing, and the finished envelope is verified
// before it is output.
type ReleaseEmitter struct {
	core *emitter
}

// NewReleaseEmitter builds an emitter from a signer and the raw
// release-v0.1 JSON Schema bytes.
func NewReleaseEmitter(signer ssh.Signer, releaseSchema []byte) (*ReleaseEmitter, error) {
	core, err := newEmitter(signer, PredicateRelease, releaseSchema)
	if err != nil {
		return nil, err
	}
	return &ReleaseEmitter{core: core}, nil
}

// Emit builds, validates, signs, and self-verifies a release attestation —
// the emit.go riders, applied to the §8.1 predicate.
func (e *ReleaseEmitter) Emit(in ReleaseInput) (Emission, error) {
	payload, err := BuildReleaseStatement(in)
	if err != nil {
		return Emission{}, err
	}
	return e.core.emit(payload, in.Timestamp)
}

// Signer returns the emitter's signing-key fingerprint — the untrusted keyid
// hint its envelopes carry (ADR-022).
func (e *ReleaseEmitter) Signer() string {
	return ssh.FingerprintSHA256(e.core.signer.PublicKey())
}
