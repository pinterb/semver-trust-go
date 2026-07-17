// SPDX-License-Identifier: Apache-2.0

package verify

// Report is the structured result of a verification run: everything §10 steps
// 1–7 produced, in a shape both the human table and --json render from. The
// per-step sections carry the §10 step they correspond to so a reader can
// trace the algorithm through the output.
type Report struct {
	Repo string `json:"repo"`
	// From is the range anchor: the CLI FROM when one was given, or — for a
	// first release under a policy-declared adoption boundary — the boundary
	// revision as declared in the policy (ADR-026).
	From     string `json:"from"`
	To       string `json:"to"`
	ToCommit string `json:"to_commit"`
	// FromIsAdoptionBoundary discloses that From is the adoption boundary
	// declared in the policy ([policy] adoption_boundary, ADR-026): history
	// before it is exempt and makes no claim. "Verified since the boundary"
	// and "verified since inception" are different claims and must never be
	// conflated, so the marker rides every rendering of a boundary-anchored
	// range.
	FromIsAdoptionBoundary bool `json:"from_is_adoption_boundary,omitempty"`
	// AdoptionBoundary is the resolved boundary commit SHA when
	// FromIsAdoptionBoundary is set (the declared revision may be a tag).
	AdoptionBoundary string `json:"adoption_boundary,omitempty"`
	Component        string `json:"component,omitempty"`
	VerifyTime       string `json:"verify_time"`

	Policy      PolicyReport      `json:"policy"`       // §10 step 1
	MetaPath    MetaPathReport    `json:"meta_path"`    // §10 step 1 / §5.4
	Commits     []CommitReport    `json:"commits"`      // §10 steps 2–3
	Derivations []DerivationReport `json:"derivations"` // §10 step 4 (non-authoritative, ADR-033)
	Scopes      []ScopeReport     `json:"scopes"`       // §10 step 5
	Propagation PropagationReport `json:"propagation"`  // §10 step 6
	Evidence    EvidenceReport    `json:"evidence"`     // §10 step 7
	// CleanChannel is the informational §6.2/ADR-032 clean-channel eligibility
	// of the target component. Nil when no propagation target resolves.
	CleanChannel *CleanChannelReport `json:"clean_channel,omitempty"`
	// PolicyState is the §5.4/ADR-028 authenticated policy state, populated only
	// in v0.10 mode (a bootstrap descriptor supplied). It is the digest-pinned
	// policy view the release/v0.2 predicate's policy_state block binds — retained
	// here so the release path reads it rather than re-deriving it. Nil in the
	// v0.3 path.
	PolicyState *PolicyStateReport `json:"policy_state,omitempty"`
}

// PolicyStateReport is the §5.4/ADR-028 authenticated policy state (release/v0.2
// policy_state). At genesis the candidate equals the active policy (candidate
// fields nil/empty) and the authority is "bootstrap".
type PolicyStateReport struct {
	ActivePolicy        PolicyDigestDescriptor   `json:"active_policy"`
	ActiveTrustRoots    []PolicyDigestDescriptor `json:"active_trust_roots"`
	CandidatePolicy     *PolicyDigestDescriptor  `json:"candidate_policy"`
	CandidateTrustRoots []PolicyDigestDescriptor `json:"candidate_trust_roots"`
	MandatoryWorkflows  []PolicyDigestDescriptor `json:"mandatory_workflows"`
	Authority           string                   `json:"authority"`
	AuthorityIdentity   PolicyDigestDescriptor   `json:"authority_identity"`
}

// PolicyDigestDescriptor pins a policy or trust-material resource: an optional
// uri/path and its digest set.
type PolicyDigestDescriptor struct {
	URI    string            `json:"uri,omitempty"`
	Path   string            `json:"path,omitempty"`
	Digest map[string]string `json:"digest"`
}

// CleanChannelReport is the informational §6.2/ADR-032 clean-channel
// eligibility of the target component's effective trust against the policy
// threshold. It is NOT a gate: ADR-032 places the threshold gate in the release
// DECISION (bound into the attestation for deterministic replay), and verify
// reports the same relationship without aborting on it. Met means the threshold
// gate alone is satisfied (effective >= threshold); the §6.4 blast/differ table
// is a separate release-time factor, so Met does not by itself mean a release
// would be clean.
type CleanChannelReport struct {
	Effective string `json:"effective"`
	Threshold string `json:"threshold"`
	Met       bool   `json:"met"`
}

// PolicyReport records the loaded policy and its pinned digest (§10 step 1,
// §8.1). Digest is the lowercase-hex SHA-256 of the in-tree policy bytes.
type PolicyReport struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	Threshold string `json:"threshold"`
	Strategy  string `json:"strategy"`
	Adapter   string `json:"graph_adapter"`
}

// MetaPathReport records the §5.4 meta-path level check (§10 step 1): the
// declared meta-paths, the required level, and — on a passing run — the empty
// violations set. A non-empty set aborts, so a rendered report always shows
// Passed true.
type MetaPathReport struct {
	Paths         []string `json:"paths"`
	RequiredLevel string   `json:"required_level"`
	Violations    []string `json:"violations"`
	Passed        bool     `json:"passed"`
}

// CommitReport is one verified commit's provenance row (§10 steps 2–3): the
// assigned level and the authorship/review classes and signer identity it was
// derived from.
type CommitReport struct {
	SHA         string   `json:"sha"`
	Short       string   `json:"short"`
	Level       string   `json:"level"`
	Authorship  string   `json:"authorship"`
	Review      string   `json:"review"`
	Signer      string   `json:"signer"`
	Fingerprint string   `json:"fingerprint"`
	Provenance  string   `json:"provenance,omitempty"`
	// Trailers is the commit's full self-asserted trailer block (§4.1),
	// advisory by definition — preserved so the release attestation's
	// provenance vector (§8.1) can carry it. First value wins per key.
	Trailers map[string]string `json:"trailers,omitempty"`
	Merge    bool              `json:"merge"`
	Paths    []string          `json:"paths"`
	// ReviewIdentity is the verified reviewer identity when a review
	// attestation was cryptographically consumed for this commit (§4.3).
	ReviewIdentity string `json:"review_identity,omitempty"`
	// ReviewAttestation references the consumed review attestation in the
	// store (refs/attestations/<sha>/<digest>) — the §8.1 attestation ref.
	ReviewAttestation string `json:"review_attestation,omitempty"`
	// ReviewNote records honest degradation (e.g. a present-but-unverifiable
	// review attestation classified none because no attestation-signers were
	// provided).
	ReviewNote string `json:"review_note,omitempty"`
}

// DerivationReport records one policy-declared derivation rule (§10 step 4).
// Derivation claims are non-authoritative metadata (spec repository ADR-033):
// the verifier never executes them and they supply no trust elevation, so
// Verified is always false and the note states why. The retired re-leveling
// fields keep their JSON names for report-shape compatibility but are never
// populated.
type DerivationReport struct {
	Rule           string   `json:"rule"`
	Verified       bool     `json:"verified"`
	InheritedLevel string   `json:"inherited_level,omitempty"`
	Diffs          []string `json:"diffs,omitempty"`
	Note           string   `json:"note,omitempty"`
}

// ScopeReport is one scope's own trust (§10 step 5, §5.2): the per-scope floor
// and the commits that touched it.
type ScopeReport struct {
	Scope    string   `json:"scope"`
	OwnFloor string   `json:"own_floor"`
	Commits  []string `json:"commits"`
}

// PropagationReport is effective trust over the workspace graph (§10 step 6,
// §5.3). With the "none" adapter there is no graph: each scope's effective
// trust is its own floor, floor-sourced to itself. With a workspace adapter,
// components carry own and effective trust and the component that set each
// floor.
type PropagationReport struct {
	Adapter    string                  `json:"adapter"`
	Target     string                  `json:"target,omitempty"`
	Components []ComponentEffective    `json:"components"`
	// Note records the v1 component↔scope mapping and any degradation.
	Note string `json:"note,omitempty"`
}

// ComponentEffective is one component's propagated trust (§5.3): its own
// floor, its effective floor after propagation, and the component whose own
// trust set the effective floor (itself when it attains its own floor).
type ComponentEffective struct {
	Name        string `json:"name"`
	Own         string `json:"own"`
	Effective   string `json:"effective"`
	FloorSource string `json:"floor_source"`
	// Dependencies are the component's direct internal dependencies from the
	// workspace graph — what a release attestation pins (§5.3, §8.1). Empty
	// with no graph adapter.
	Dependencies []string `json:"dependencies,omitempty"`
}

// EvidenceReport is the honest v1 evidence collection (§10 step 7, §6). Blast
// inputs come from git where universal (changed files); LOC, fan-in, and
// coverage require evidence providers not wired in v1 and are reported
// unavailable rather than fabricated (§1.1, honest degradation). The semantic
// floor comes from a configured compatibility differ when one applies, else
// from declared intent (§6.1).
type EvidenceReport struct {
	ChangedFiles        int    `json:"changed_files"`
	LOCAvailable        bool   `json:"loc_available"`
	SemanticFloor       string `json:"semantic_floor"`
	SemanticFloorSource string `json:"semantic_floor_source"`
	DifferAvailable     bool   `json:"differ_available"`
	DifferProvider      string `json:"differ_provider,omitempty"`
	BlastScore          string `json:"blast_score"`
	Note                string `json:"note,omitempty"`
}
