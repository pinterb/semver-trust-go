// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
	"github.com/semver-trust/semver-trust-go/internal/version"
)

// This file is the accepted-predecessor reader (§7.5/ADR-027/028/029, #76 M6
// Phase C): the recurrence counterpart of the genesis BootstrapDescriptor. It
// discovers, FRESH-VERIFIES, and projects the accepted chain head for a
// (repository, component) so the ported recurring evaluators — vcs.SelectInterval,
// policy.SelectPolicyTransition, version.SelectVersionAncestry — can run against a
// real second/Nth release. `Accepted`/`ChainHead` are established HERE by fresh
// verification and unique-head cardinality, never taken from a payload claim.
//
// ADR-027 requires the predecessor's "signature and complete chain MUST verify."
// That is realized structurally: each release/v0.2 binds its predecessor via two
// on-wire links — version_state.predecessor (the predecessor's emitted tag) and
// version_state.prior_state.digest (== the predecessor's resulting_state.digest,
// the ADR-036 hash-chain link). AcceptedChainHead reconstructs each release's
// version.VersionState from its wire block and checks that
// StateDigest(CanonicalStateMap(…, prior_state.digest)) reproduces the signed
// resulting_state.digest, then walks genesis→head confirming every prior_state
// link resolves to a known release's resulting_state. A tampered state, a broken
// link, or a fork aborts.

// Predecessor is the accepted, fresh-verified chain head for a (repository,
// component): the authority a recurring release derives its interval, policy
// transition, and version line from. It is produced only by AcceptedChainHead.
type Predecessor struct {
	repository string
	component  string
	tagPrefix  string

	head  verifiedRelease
	state version.VersionState // the head's reconstructed, digest-verified resulting state

	// tagTarget is the head's emitted tag re-resolved against the current repo. It
	// always equals the head's TO: AcceptedChainHead refuses to return a
	// predecessor whose tag is absent, moved, or recreated (§5.2/ADR-027), so a
	// live-but-divergent tag never reaches the interval evaluator.
	tagTarget string
}

// verifiedRelease is one fresh-verified release/v0.2 in the chain with the parsed
// facts the reader needs.
type verifiedRelease struct {
	doc          releaseV02Doc
	to           string // subject digest.gitCommit (this release's TO)
	tag          string // subject name (this release's emitted tag)
	resultDigest string // resulting_state.digest sha256 (bare hex)
	priorDigest  string // prior_state.digest sha256 (bare hex), "" at genesis
}

// AcceptedChainHead discovers the accepted chain head for (repository, component)
// among the release/v0.2 attestations stored in repoPath, or returns (nil, nil)
// when none exists (chain genesis — the caller stays on the descriptor authority,
// exactly as M1–M3). It enumerates every stored attestation, fresh-verifies each
// with v (an attestation that does not verify is not a trustworthy chain member
// and is skipped, so a broken link surfaces later as a disconnected chain rather
// than a silently-trusted one), keeps the verified release/v0.2 for this
// component, selects the unique head (the release no other names as predecessor),
// verifies the complete hash-chain back to genesis, and confirms the head's emitted
// tag still resolves to the signed binding. A fork (2+ heads), a cycle (0 heads
// among ≥1 release), a broken link, a digest mismatch, or a missing/moved/recreated
// head tag aborts.
func AcceptedChainHead(repoPath, repository, component string, v *attest.Verifier, at time.Time) (*Predecessor, error) {
	envelopes, err := (attest.GitRefStore{Path: repoPath}).All()
	if err != nil {
		return nil, fmt.Errorf("accepted-predecessor: enumerating attestations: %w", err)
	}

	releases, err := verifiedReleasesFor(repository, component, envelopes, v, at)
	if err != nil {
		return nil, err
	}
	if len(releases) == 0 {
		return nil, nil // genesis: no accepted chain head yet
	}

	head, err := selectUniqueHead(releases)
	if err != nil {
		return nil, err
	}

	// tag_prefix is a chain invariant; take it from the head.
	tagPrefix := head.doc.Predicate.Component.TagPrefix
	headState, err := verifyCompleteChain(head, releases, component, tagPrefix)
	if err != nil {
		return nil, err
	}

	// The accepted predecessor's tag MUST still resolve to P, and to the exact
	// signed binding (§5.2/ADR-027, §7.5/ADR-029): a missing, moved, or recreated
	// tag breaks continuity — and, per PR #107's no-orphan-tag discipline, an
	// attestation whose tag is gone must not become the head the next recurring
	// release chains to. Assert the live ref matches version_state.emission.tag on
	// both the peeled commit OID and the raw ref OID.
	em := head.doc.Predicate.VersionState.Emission.Tag
	if em == nil {
		return nil, fmt.Errorf("accepted-predecessor: head %q binds no emission.tag", head.tag)
	}
	tagRefs, err := vcs.TagRefs(repoPath)
	if err != nil {
		return nil, fmt.Errorf("accepted-predecessor: resolving tags: %w", err)
	}
	ref, ok := tagRefs[head.tag]
	if !ok {
		return nil, fmt.Errorf("accepted-predecessor: head tag %q is absent from the repository — the accepted predecessor's tag must still resolve to P (§5.2/ADR-027)", head.tag)
	}
	if ref.CommitOID != em.PeeledCommitOID {
		return nil, fmt.Errorf("accepted-predecessor: head tag %q peels to %s, not the signed emission.tag.peeled_commit_oid %s — the ref has moved (§5.2/ADR-027)", head.tag, ref.CommitOID, em.PeeledCommitOID)
	}
	if ref.RefOID != em.RawRefOID {
		return nil, fmt.Errorf("accepted-predecessor: head tag %q raw ref %s does not match the signed emission.tag.raw_ref_oid %s — the tag was recreated (§7.5/ADR-029)", head.tag, ref.RefOID, em.RawRefOID)
	}

	return &Predecessor{
		repository: repository,
		component:  component,
		tagPrefix:  tagPrefix,
		head:       head,
		state:      headState,
		tagTarget:  ref.CommitOID,
	}, nil
}

// verifiedReleasesFor fresh-verifies every envelope and returns the release/v0.2
// attestations for (repository, component). An envelope that fails verification
// (bad signature, unknown signer, unsupported predicate, schema) is skipped: it is
// not a trustworthy chain member, and a genuinely missing link is caught later as
// a broken chain, not silently trusted.
func verifiedReleasesFor(repository, component string, envelopes [][]byte, v *attest.Verifier, at time.Time) ([]verifiedRelease, error) {
	var releases []verifiedRelease
	seen := map[string]bool{} // resulting-state digest → dedup identical chain members
	for _, env := range envelopes {
		stmt, err := v.Verify(env, at)
		if err != nil {
			continue
		}
		if stmt.PredicateType != attest.PredicateReleaseV02 {
			continue
		}
		var doc releaseV02Doc
		if err := json.Unmarshal(stmt.Payload, &doc); err != nil {
			continue
		}
		if doc.Predicate.Repository.ID != repository || doc.Predicate.Component.Name != component {
			continue
		}
		r, err := newVerifiedRelease(doc)
		if err != nil {
			return nil, err
		}
		if seen[r.resultDigest] {
			continue
		}
		seen[r.resultDigest] = true
		releases = append(releases, r)
	}
	return releases, nil
}

// newVerifiedRelease extracts the subject and version-state linkage a verified
// release/v0.2 contributes to the chain.
func newVerifiedRelease(doc releaseV02Doc) (verifiedRelease, error) {
	if len(doc.Subject) != 1 {
		return verifiedRelease{}, fmt.Errorf("accepted-predecessor: release/v0.2 must carry exactly one subject, has %d", len(doc.Subject))
	}
	to := doc.Subject[0].Digest["gitCommit"]
	if to == "" {
		return verifiedRelease{}, fmt.Errorf("accepted-predecessor: release/v0.2 subject %q carries no gitCommit digest", doc.Subject[0].Name)
	}
	vs := doc.Predicate.VersionState
	result := vs.ResultingState.Digest["sha256"]
	if result == "" {
		return verifiedRelease{}, fmt.Errorf("accepted-predecessor: release/v0.2 for %q carries no resulting_state sha256 digest", doc.Subject[0].Name)
	}
	var prior string
	if vs.PriorState != nil {
		prior = vs.PriorState.Digest["sha256"]
	}
	return verifiedRelease{
		doc:          doc,
		to:           to,
		tag:          doc.Subject[0].Name,
		resultDigest: result,
		priorDigest:  prior,
	}, nil
}

// selectUniqueHead returns the chain head — the release whose resulting state no
// other release names as its prior state. Exactly one such head must exist; a
// fork (2+) or a cycle (0 among ≥1) aborts.
func selectUniqueHead(releases []verifiedRelease) (verifiedRelease, error) {
	isPredecessor := map[string]bool{}
	for _, r := range releases {
		if r.priorDigest != "" {
			isPredecessor[r.priorDigest] = true
		}
	}
	var heads []verifiedRelease
	for _, r := range releases {
		if !isPredecessor[r.resultDigest] {
			heads = append(heads, r)
		}
	}
	switch len(heads) {
	case 1:
		return heads[0], nil
	case 0:
		return verifiedRelease{}, fmt.Errorf("accepted-predecessor: no chain head among %d release(s) — the chain has a cycle", len(releases))
	default:
		return verifiedRelease{}, fmt.Errorf("accepted-predecessor: %d conflicting chain heads for the component — the accepted head is ambiguous (§7.5/ADR-027)", len(heads))
	}
}

// verifyCompleteChain walks genesis→head. For each release it reconstructs the
// version.VersionState from the wire block and checks that its ADR-036 digest
// reproduces the signed resulting_state.digest (catching a tampered or lying
// emitter), then follows prior_state.digest to a known release and confirms the
// version_state.predecessor tag matches that release's emitted tag. It returns the
// head's reconstructed state (the recurring version authority's carried state).
func verifyCompleteChain(head verifiedRelease, releases []verifiedRelease, component, tagPrefix string) (version.VersionState, error) {
	byResult := make(map[string]verifiedRelease, len(releases))
	for _, r := range releases {
		byResult[r.resultDigest] = r
	}

	var headState version.VersionState
	cur := head
	visited := map[string]bool{}
	for {
		if visited[cur.resultDigest] {
			return version.VersionState{}, fmt.Errorf("accepted-predecessor: chain cycle at %s", cur.tag)
		}
		visited[cur.resultDigest] = true

		state, err := reconstructState(cur.doc, tagPrefix)
		if err != nil {
			return version.VersionState{}, fmt.Errorf("accepted-predecessor: reconstructing state for %s: %w", cur.tag, err)
		}
		var priorPtr *string
		if cur.priorDigest != "" {
			p := "sha256:" + cur.priorDigest
			priorPtr = &p
		}
		got, err := version.StateDigest(version.CanonicalStateMap(component, tagPrefix, state, priorPtr))
		if err != nil {
			return version.VersionState{}, fmt.Errorf("accepted-predecessor: canonicalizing state for %s: %w", cur.tag, err)
		}
		if got != cur.resultDigest {
			return version.VersionState{}, fmt.Errorf("accepted-predecessor: state digest for %s does not reproduce its signed resulting_state.digest (chain tampered, §8.1/ADR-036)", cur.tag)
		}
		if cur.resultDigest == head.resultDigest {
			headState = state
		}

		if cur.doc.Predicate.VersionState.Genesis {
			if cur.priorDigest != "" {
				return version.VersionState{}, fmt.Errorf("accepted-predecessor: genesis release %s binds a prior_state — a genesis state has no predecessor (§7.5/ADR-029)", cur.tag)
			}
			return headState, nil
		}

		if cur.priorDigest == "" {
			return version.VersionState{}, fmt.Errorf("accepted-predecessor: non-genesis release %s binds no prior_state — the chain link is missing", cur.tag)
		}
		prev, ok := byResult[cur.priorDigest]
		if !ok {
			return version.VersionState{}, fmt.Errorf("accepted-predecessor: %s names a predecessor state not present in the store — the chain is broken (§7.5/ADR-027)", cur.tag)
		}
		// The two linkages must agree: the tag the successor pins as its
		// predecessor must be the previous release's emitted tag identity — in
		// FULL: name, peeled commit OID, AND raw ref OID. The raw ref OID matters
		// because ADR-036 excludes emission from resulting_state.digest, so the
		// previous release's emission.tag.raw_ref_oid is not covered by its own
		// signed digest; a successor that consistently binds a forged predecessor
		// raw ref still reproduces its own digest, so this is the only place the
		// forgery is caught.
		prevEm := prev.doc.Predicate.VersionState.Emission.Tag
		if prevEm == nil {
			return version.VersionState{}, fmt.Errorf("accepted-predecessor: linked release %s binds no emission.tag", prev.tag)
		}
		pred := cur.doc.Predicate.VersionState.Predecessor
		if pred == nil {
			return version.VersionState{}, fmt.Errorf("accepted-predecessor: non-genesis release %s binds a null version_state.predecessor", cur.tag)
		}
		if pred.Name != prevEm.Name || pred.PeeledCommitOID != prevEm.PeeledCommitOID || pred.RawRefOID != prevEm.RawRefOID {
			return version.VersionState{}, fmt.Errorf("accepted-predecessor: %s predecessor tag identity {%s, raw %s, peeled %s} does not match the linked release's emitted tag {%s, raw %s, peeled %s}",
				cur.tag, pred.Name, pred.RawRefOID, pred.PeeledCommitOID, prevEm.Name, prevEm.RawRefOID, prevEm.PeeledCommitOID)
		}
		cur = prev
	}
}

// reconstructState rebuilds the version.VersionState a release canonicalized (its
// resulting state) from the release/v0.2 wire block. baseline_core and
// clean_accepted are not top-level wire fields but are recoverable: baseline_core
// is the core of version_state.predecessor.name (or "0.0.0" for a new line), and
// clean_accepted is whether the emitted tag carries no trust suffix. The
// reconstruction mirrors how the emitter (release CLI) builds the state, so its
// ADR-036 digest reproduces.
func reconstructState(doc releaseV02Doc, tagPrefix string) (version.VersionState, error) {
	vs := doc.Predicate.VersionState

	var baseline *version.Binding
	baselineCore := "0.0.0"
	if vs.Predecessor != nil {
		baseline = &version.Binding{Tag: vs.Predecessor.Name, RefOID: vs.Predecessor.RawRefOID, CommitOID: vs.Predecessor.PeeledCommitOID}
		pv, err := version.Parse(vs.Predecessor.Name)
		if err != nil {
			return version.VersionState{}, fmt.Errorf("predecessor tag %q: %w", vs.Predecessor.Name, err)
		}
		baselineCore = fmt.Sprintf("%d.%d.%d", pv.Major, pv.Minor, pv.Patch)
	}

	if vs.Emission.Tag == nil {
		return version.VersionState{}, fmt.Errorf("a stored release binds no emission.tag (kind %q)", vs.Emission.Kind)
	}
	emitted, err := version.Parse(vs.Emission.Tag.Name)
	if err != nil {
		return version.VersionState{}, fmt.Errorf("emitted tag %q: %w", vs.Emission.Tag.Name, err)
	}
	cleanAccepted := emitted.Trust == nil
	iterations := map[string]int{}
	if emitted.Trust != nil {
		iterations[fmt.Sprintf("T%d", emitted.Trust.Level)] = int(emitted.Trust.Iteration)
	}

	lineage := make([]string, len(vs.TargetLineage))
	for i, l := range vs.TargetLineage {
		lineage[i] = l.ID
	}

	return version.VersionState{
		Baseline:        baseline,
		BaselineCore:    baselineCore,
		TargetCore:      vs.TargetCore,
		TargetBump:      vs.TargetBump,
		CleanAccepted:   cleanAccepted,
		TargetIntervals: lineage,
		Iterations:      iterations,
		CorrectiveFloor: vs.PendingCorrectiveFloor,
	}, nil
}

// IntervalDescriptor projects the head as the §5.2/ADR-027 recurring interval
// authority (vcs.PredecessorDescriptor). TagTarget is the head's tag re-resolved
// against the current repo, so a moved predecessor tag is refused by the
// evaluator.
func (p *Predecessor) IntervalDescriptor() vcs.PredecessorDescriptor {
	return vcs.PredecessorDescriptor{
		Accepted:   true,
		ChainHead:  true,
		Repository: p.repository,
		Component:  p.component,
		To:         p.head.to,
		TagTarget:  p.tagTarget,
	}
}

// VersionSelected projects the head as the §7.5/ADR-029 recurring version
// authority (version.VersionSelected), carrying the head's reconstructed,
// digest-verified resulting state. SourceSuccessorExists is false: the head is by
// definition the release no successor has advanced past.
func (p *Predecessor) VersionSelected() version.VersionSelected {
	em := p.head.doc.Predicate.VersionState.Emission.Tag
	return version.VersionSelected{
		Accepted:              true,
		ChainHead:             true,
		SourceSuccessorExists: false,
		Repository:            p.repository,
		Component:             p.component,
		TagPrefix:             p.tagPrefix,
		To:                    p.head.to,
		CanonicalTags:         []version.Binding{{Tag: em.Name, RefOID: em.RawRefOID, CommitOID: em.PeeledCommitOID}},
		State:                 p.state,
	}
}

// ResultingStateDigest is the head's resulting_state.digest as "sha256:<hex>" —
// the hash-chain link a recurring successor binds as its prior_state.digest and
// feeds to CanonicalStateMap as predecessorStateDigest (§8.1/ADR-036).
func (p *Predecessor) ResultingStateDigest() string {
	return "sha256:" + p.head.resultDigest
}

// To is the head's release-target commit (the recurring interval's P).
func (p *Predecessor) To() string { return p.head.to }

// Tag is the head's emitted tag name.
func (p *Predecessor) Tag() string { return p.head.tag }

// PolicyPins are the head's authenticated §5.4/ADR-028 policy facts — the anchors
// a recurring policy transition authenticates the active policy against. Profiles
// and trust roles are chain-invariant and not on the wire; the transition wiring
// (C2/C3) combines these pins with the active MetaPolicy it derives.
type PolicyPins struct {
	PolicyPath         string
	PolicyDigest       string // sha256:<hex>
	TrustMaterial      map[string]string
	MandatoryMetaPaths []string
	AuthorityURI       string
	AuthorityDigest    string // sha256:<hex>
}

// PolicyPins projects the head's active policy_state pins.
func (p *Predecessor) PolicyPins() PolicyPins {
	ps := p.head.doc.Predicate.PolicyState
	material := map[string]string{}
	for _, r := range ps.ActiveTrustRoots {
		material[digestDescPath(r)] = digestString(r.Digest)
	}
	workflows := make([]string, 0, len(ps.MandatoryWorkflows))
	for _, w := range ps.MandatoryWorkflows {
		workflows = append(workflows, digestDescPath(w))
	}
	return PolicyPins{
		PolicyPath:         ps.ActivePolicy.Path,
		PolicyDigest:       digestString(ps.ActivePolicy.Digest),
		TrustMaterial:      material,
		MandatoryMetaPaths: workflows,
		AuthorityURI:       ps.AuthorityIdentity.URI,
		AuthorityDigest:    digestString(ps.AuthorityIdentity.Digest),
	}
}

func digestString(d map[string]string) string {
	if h := d["sha256"]; h != "" {
		return "sha256:" + h
	}
	return ""
}

func digestDescPath(d digestDescriptor) string { return d.Path }

// releaseV02Doc is a narrow read view of the frozen release/v0.2 statement — only
// the fields the accepted-predecessor reader projects. It is coupled to the
// schema-pinned wire shape (conformance/vendor/schemas/release-v0.2.json), which
// the emitter in internal/attest/release_v02.go produces.
type releaseV02Doc struct {
	Subject       []attestSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     struct {
		Repository struct {
			ID string `json:"id"`
		} `json:"repository"`
		Component struct {
			Name      string `json:"name"`
			TagPrefix string `json:"tag_prefix"`
		} `json:"component"`
		Interval struct {
			Mode string `json:"mode"`
		} `json:"interval"`
		PolicyState struct {
			ActivePolicy       digestDescriptor   `json:"active_policy"`
			ActiveTrustRoots   []digestDescriptor `json:"active_trust_roots"`
			MandatoryWorkflows []digestDescriptor `json:"mandatory_workflows"`
			Authority          string             `json:"authority"`
			AuthorityIdentity  digestDescriptor   `json:"authority_identity"`
		} `json:"policy_state"`
		VersionState struct {
			Action                 string             `json:"action"`
			Genesis                bool               `json:"genesis"`
			Predecessor            *tagIdentity       `json:"predecessor"`
			PriorState             *stateIdentity     `json:"prior_state"`
			ResultingState         stateIdentity      `json:"resulting_state"`
			TargetCore             string             `json:"target_core"`
			TargetBump             string             `json:"target_bump"`
			Emission               tagEmission        `json:"emission"`
			TargetLineage          []objectIdentity   `json:"target_lineage"`
			Iteration              *int               `json:"iteration"`
			PendingCorrectiveFloor *string            `json:"pending_corrective_floor"`
		} `json:"version_state"`
	} `json:"predicate"`
}

type attestSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type digestDescriptor struct {
	URI    string            `json:"uri"`
	Path   string            `json:"path"`
	Digest map[string]string `json:"digest"`
}

type tagIdentity struct {
	Name            string `json:"name"`
	RawRefOID       string `json:"raw_ref_oid"`
	PeeledCommitOID string `json:"peeled_commit_oid"`
}

type stateIdentity struct {
	ID     string            `json:"id"`
	Digest map[string]string `json:"digest"`
}

type tagEmission struct {
	Kind string       `json:"kind"`
	Tag  *tagIdentity `json:"tag"`
}

type objectIdentity struct {
	ID string `json:"id"`
}
