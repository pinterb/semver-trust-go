// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
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
	envelope     []byte // the raw verified envelope (for the attestation identity)
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
	return acceptedHead(repoPath, repository, component, "", v, at)
}

// AcceptedChainHeadBoundTo is AcceptedChainHead that additionally binds the chain to
// the supplied bootstrap descriptor: the genesis release MUST record that descriptor
// as its §5.4/ADR-028 bootstrap authority — policy_state.authority == "bootstrap",
// authority_identity.uri == "bootstrap:<component>", and authority_identity.digest ==
// bootstrapDigest (the descriptor's Digest(), "sha256:<hex>"). It rejects a chain
// that verifies internally but was bootstrapped by a DIFFERENT descriptor sharing the
// same repository/component — the binding `verify --chain-head` needs so the reported
// head is the one THIS descriptor authorized, not merely one with a matching subject.
func AcceptedChainHeadBoundTo(repoPath, repository, component, bootstrapDigest string, v *attest.Verifier, at time.Time) (*Predecessor, error) {
	return acceptedHead(repoPath, repository, component, bootstrapDigest, v, at)
}

func acceptedHead(repoPath, repository, component, bootstrapDigest string, v *attest.Verifier, at time.Time) (*Predecessor, error) {
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
	states, err := verifyCompleteChain(head, releases, component, tagPrefix, bootstrapDigest)
	if err != nil {
		return nil, err
	}
	return buildPredecessor(repoPath, repository, component, tagPrefix, head, states[head.resultDigest])
}

// buildPredecessor projects a verified chain member r (with its reconstructed
// carried state) into a *Predecessor, confirming its emitted tag still resolves to
// the signed binding (§5.2/ADR-027, §7.5/ADR-029): a missing, moved, or recreated
// tag breaks continuity — and, per PR #107's no-orphan discipline, an attestation
// whose tag is gone must not become an authority.
func buildPredecessor(repoPath, repository, component, tagPrefix string, r verifiedRelease, state version.VersionState) (*Predecessor, error) {
	em := r.doc.Predicate.VersionState.Emission.Tag
	if em == nil {
		return nil, fmt.Errorf("accepted-predecessor: %q binds no emission.tag", r.tag)
	}
	tagRefs, err := vcs.TagRefs(repoPath)
	if err != nil {
		return nil, fmt.Errorf("accepted-predecessor: resolving tags: %w", err)
	}
	ref, ok := tagRefs[r.tag]
	if !ok {
		return nil, fmt.Errorf("accepted-predecessor: tag %q is absent from the repository — it must still resolve to its commit (§5.2/ADR-027)", r.tag)
	}
	if ref.CommitOID != em.PeeledCommitOID {
		return nil, fmt.Errorf("accepted-predecessor: tag %q peels to %s, not the signed emission.tag.peeled_commit_oid %s — the ref has moved (§5.2/ADR-027)", r.tag, ref.CommitOID, em.PeeledCommitOID)
	}
	if ref.RefOID != em.RawRefOID {
		return nil, fmt.Errorf("accepted-predecessor: tag %q raw ref %s does not match the signed emission.tag.raw_ref_oid %s — the tag was recreated (§7.5/ADR-029)", r.tag, ref.RefOID, em.RawRefOID)
	}
	return &Predecessor{
		repository: repository,
		component:  component,
		tagPrefix:  tagPrefix,
		head:       r,
		state:      state,
		tagTarget:  ref.CommitOID,
	}, nil
}

// SupersedeHead resolves the accepted chain head — the release a promotion
// supersedes — and its OWN predecessor, the interval/policy anchor for re-verifying
// the superseded's source range (nil when the superseded is a genesis release; then
// the descriptor's genesis interval is re-run). Returns (nil, nil, nil) when the
// component has no chain head. The head and anchor are established by the same fresh
// verification + complete-chain walk as AcceptedChainHead.
func SupersedeHead(repoPath, repository, component string, v *attest.Verifier, at time.Time) (superseded, anchor *Predecessor, err error) {
	envelopes, err := (attest.GitRefStore{Path: repoPath}).All()
	if err != nil {
		return nil, nil, fmt.Errorf("accepted-predecessor: enumerating attestations: %w", err)
	}
	releases, err := verifiedReleasesFor(repository, component, envelopes, v, at)
	if err != nil {
		return nil, nil, err
	}
	if len(releases) == 0 {
		return nil, nil, nil
	}
	head, err := selectUniqueHead(releases)
	if err != nil {
		return nil, nil, err
	}
	tagPrefix := head.doc.Predicate.Component.TagPrefix
	states, err := verifyCompleteChain(head, releases, component, tagPrefix, "")
	if err != nil {
		return nil, nil, err
	}
	superseded, err = buildPredecessor(repoPath, repository, component, tagPrefix, head, states[head.resultDigest])
	if err != nil {
		return nil, nil, err
	}
	if !head.doc.Predicate.VersionState.Genesis {
		byResult := make(map[string]verifiedRelease, len(releases))
		for _, r := range releases {
			byResult[r.resultDigest] = r
		}
		prev := byResult[head.priorDigest]
		anchor, err = buildPredecessor(repoPath, repository, component, tagPrefix, prev, states[prev.resultDigest])
		if err != nil {
			return nil, nil, err
		}
	}
	return superseded, anchor, nil
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
		r.envelope = env
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

// verifyCompleteChain verifies the chain genesis→head and returns the head's
// reconstructed carried-forward state. It collects the chain by following
// prior_state.digest from the head (confirming each version_state.predecessor tag
// identity — name, peeled AND raw ref OID — matches the linked release's emitted
// tag; the raw ref matters because ADR-036 excludes emission from the digest, so a
// self-consistent forged predecessor raw ref is caught only here), then walks it
// forward reconstructing each state and checking its ADR-036 digest reproduces the
// signed resulting_state.digest. The forward walk carries the BASELINE: an advance
// sets the baseline to its version_state.predecessor, a recut PRESERVES it (its
// canonical baseline is the last advance's, which differs from the chain
// predecessor it links to), so the baseline cannot be read from one release's wire
// alone.
func verifyCompleteChain(head verifiedRelease, releases []verifiedRelease, component, tagPrefix, bootstrapDigest string) (map[string]version.VersionState, error) {
	byResult := make(map[string]verifiedRelease, len(releases))
	for _, r := range releases {
		byResult[r.resultDigest] = r
	}

	// Collect head→genesis, checking the linkage at each step.
	var chainOrder []verifiedRelease // head-first; reversed to genesis-first below
	cur := head
	visited := map[string]bool{}
	for {
		if visited[cur.resultDigest] {
			return nil, fmt.Errorf("accepted-predecessor: chain cycle at %s", cur.tag)
		}
		visited[cur.resultDigest] = true
		chainOrder = append(chainOrder, cur)

		if cur.doc.Predicate.VersionState.Genesis {
			if cur.priorDigest != "" {
				return nil, fmt.Errorf("accepted-predecessor: genesis release %s binds a prior_state — a genesis state has no predecessor (§7.5/ADR-029)", cur.tag)
			}
			// Bind the chain to the supplied bootstrap descriptor (§5.4/ADR-028): the
			// genesis release must record THIS descriptor as its bootstrap authority.
			// The chain's signatures/links can be internally consistent yet have been
			// bootstrapped by a different descriptor with the same repository/component,
			// so the descriptor→chain binding is proven HERE, against the genesis's
			// authority identity, not merely by matching the subject.
			if bootstrapDigest != "" {
				ps := cur.doc.Predicate.PolicyState
				gotDigest := "sha256:" + ps.AuthorityIdentity.Digest["sha256"]
				wantURI := "bootstrap:" + component
				if ps.Authority != "bootstrap" || ps.AuthorityIdentity.URI != wantURI || gotDigest != bootstrapDigest {
					return nil, fmt.Errorf("accepted-predecessor: genesis release %s was not bootstrapped by the supplied descriptor (authority %q, identity %s %s; want bootstrap %s %s) — §5.4/ADR-028",
						cur.tag, ps.Authority, ps.AuthorityIdentity.URI, gotDigest, wantURI, bootstrapDigest)
				}
			}
			break
		}
		if cur.priorDigest == "" {
			return nil, fmt.Errorf("accepted-predecessor: non-genesis release %s binds no prior_state — the chain link is missing", cur.tag)
		}
		prev, ok := byResult[cur.priorDigest]
		if !ok {
			return nil, fmt.Errorf("accepted-predecessor: %s names a predecessor state not present in the store — the chain is broken (§7.5/ADR-027)", cur.tag)
		}
		prevEm := prev.doc.Predicate.VersionState.Emission.Tag
		if prevEm == nil {
			return nil, fmt.Errorf("accepted-predecessor: linked release %s binds no emission.tag", prev.tag)
		}
		pred := cur.doc.Predicate.VersionState.Predecessor
		if pred == nil {
			return nil, fmt.Errorf("accepted-predecessor: non-genesis release %s binds a null version_state.predecessor", cur.tag)
		}
		if pred.Name != prevEm.Name || pred.PeeledCommitOID != prevEm.PeeledCommitOID || pred.RawRefOID != prevEm.RawRefOID {
			return nil, fmt.Errorf("accepted-predecessor: %s predecessor tag identity {%s, raw %s, peeled %s} does not match the linked release's emitted tag {%s, raw %s, peeled %s}",
				cur.tag, pred.Name, pred.RawRefOID, pred.PeeledCommitOID, prevEm.Name, prevEm.RawRefOID, prevEm.PeeledCommitOID)
		}
		// A supersede re-evaluates the SAME commit: its subject must be the superseded
		// release's TO (§7.5/ADR-029). An advance/recut moves to a new TO. Only a
		// PROMOTION supersede (emits a tag) is a chain head; the attestation-only
		// outcomes (kind "none") do not advance the head.
		if cur.doc.Predicate.VersionState.Action == "supersede" {
			if cur.doc.Predicate.VersionState.Emission.Kind != "tag" {
				return nil, fmt.Errorf("accepted-predecessor: supersede release %s emits no tag (kind %q) — an attestation-only supersede is not a chain head", cur.tag, cur.doc.Predicate.VersionState.Emission.Kind)
			}
			if cur.to != prev.to {
				return nil, fmt.Errorf("accepted-predecessor: supersede release %s is at %s, not the superseded release %s's commit %s — a supersede re-evaluates the same commit", cur.tag, cur.to, prev.tag, prev.to)
			}
			// It MUST also bind decision.supersedes to the predecessor attestation it
			// supersedes — the same stable ref (and digest, if present) the promotion
			// path emits (§7.3). prior_state links the STATE; supersedes links the
			// ATTESTATION, and a promotion is only complete when it names both.
			if err := checkSupersedes(cur, prev); err != nil {
				return nil, err
			}
		}
		cur = prev
	}

	// Walk genesis→head, carrying the baseline forward from the last advance.
	var carriedBaseline *version.Binding
	carriedBaselineCore := "0.0.0"
	states := make(map[string]version.VersionState, len(chainOrder))
	for i := len(chainOrder) - 1; i >= 0; i-- {
		r := chainOrder[i]
		vs := r.doc.Predicate.VersionState
		// A chain member must carry a supported action for its position. Genesis is
		// always an advance. A recurring member is advance, recut, or a PROMOTION
		// supersede — the promotion of an unpromoted target to its clean tag, the one
		// supersede outcome that emits a tag and so becomes a chain head. The
		// attestation-only supersede outcomes (late supersession, demotion, under-bump
		// invalidation) emit no tag (emission.kind "none") and do not advance the head;
		// they are rejected as chain heads here (deferred), so a self-consistent
		// tagless supersede cannot be reconstructed as a head and a genesis cannot
		// claim a non-advance action.
		switch {
		case vs.Genesis && vs.Action != "advance":
			return nil, fmt.Errorf("accepted-predecessor: genesis release %s has action %q, want advance (§7.5/ADR-029)", r.tag, vs.Action)
		case !vs.Genesis && vs.Action != "advance" && vs.Action != "recut" && vs.Action != "supersede":
			return nil, fmt.Errorf("accepted-predecessor: release %s has unsupported chain action %q (want advance, recut, or a promotion supersede)", r.tag, vs.Action)
		}
		var baseline *version.Binding
		var baselineCore string
		if vs.Action == "recut" || vs.Action == "supersede" {
			// recut and supersede PRESERVE the target and therefore its baseline.
			baseline, baselineCore = carriedBaseline, carriedBaselineCore
		} else {
			// advance / genesis: the baseline is this release's version predecessor.
			b, core, err := baselineFromPredecessor(vs)
			if err != nil {
				return nil, fmt.Errorf("accepted-predecessor: %s: %w", r.tag, err)
			}
			baseline, baselineCore = b, core
			carriedBaseline, carriedBaselineCore = b, core
		}

		state, err := reconstructState(r.doc, baseline, baselineCore)
		if err != nil {
			return nil, fmt.Errorf("accepted-predecessor: reconstructing state for %s: %w", r.tag, err)
		}
		var priorPtr *string
		if r.priorDigest != "" {
			pd := "sha256:" + r.priorDigest
			priorPtr = &pd
		}
		got, err := version.StateDigest(version.CanonicalStateMap(component, tagPrefix, state, priorPtr))
		if err != nil {
			return nil, fmt.Errorf("accepted-predecessor: canonicalizing state for %s: %w", r.tag, err)
		}
		if got != r.resultDigest {
			return nil, fmt.Errorf("accepted-predecessor: state digest for %s does not reproduce its signed resulting_state.digest (chain tampered, §8.1/ADR-036)", r.tag)
		}
		states[r.resultDigest] = state
	}
	return states, nil
}

// checkSupersedes verifies a supersede release's decision.supersedes identifies the
// predecessor attestation it supersedes: the same stable store ref
// attest.EnvelopeRef(prev.to, prev.envelope), and — when the object identity carries
// a digest — the predecessor envelope's content digest.
func checkSupersedes(cur, prev verifiedRelease) error {
	sup := cur.doc.Predicate.Decision.Supersedes
	if sup == nil {
		return fmt.Errorf("accepted-predecessor: supersede release %s binds a null decision.supersedes — a promotion must name the attestation it supersedes (§7.3)", cur.tag)
	}
	wantRef := attest.EnvelopeRef(prev.to, prev.envelope)
	if sup.ID != wantRef {
		return fmt.Errorf("accepted-predecessor: supersede release %s decision.supersedes %q does not identify the superseded attestation %q", cur.tag, sup.ID, wantRef)
	}
	if h := sup.Digest["sha256"]; h != "" {
		sum := sha256.Sum256(prev.envelope)
		if got := hex.EncodeToString(sum[:]); h != got {
			return fmt.Errorf("accepted-predecessor: supersede release %s decision.supersedes digest %s does not match the superseded attestation digest %s", cur.tag, h, got)
		}
	}
	return nil
}

// baselineFromPredecessor derives an advance/genesis baseline binding + core from
// version_state.predecessor (nil → the synthetic 0.0.0 genesis baseline).
func baselineFromPredecessor(vs versionStateDoc) (*version.Binding, string, error) {
	if vs.Predecessor == nil {
		return nil, "0.0.0", nil
	}
	pv, err := version.Parse(vs.Predecessor.Name)
	if err != nil {
		return nil, "", fmt.Errorf("predecessor tag %q: %w", vs.Predecessor.Name, err)
	}
	return &version.Binding{Tag: vs.Predecessor.Name, RefOID: vs.Predecessor.RawRefOID, CommitOID: vs.Predecessor.PeeledCommitOID},
		fmt.Sprintf("%d.%d.%d", pv.Major, pv.Minor, pv.Patch), nil
}

// reconstructState rebuilds the version.VersionState a release canonicalized (its
// resulting state) from its wire block plus the chain-carried baseline (advance:
// its own version predecessor; recut: the preserved baseline). clean_accepted and
// the iterations come from the emitted tag. The reconstruction mirrors how the
// emitter (release CLI) builds the state, so its ADR-036 digest reproduces.
func reconstructState(doc releaseV02Doc, baseline *version.Binding, baselineCore string) (version.VersionState, error) {
	vs := doc.Predicate.VersionState

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

// ClaimedBump is the head's decision.claimed_bump — the change-set classification a
// promotion carries over unchanged (§7.3: the same source, only the evidence moved).
func (p *Predecessor) ClaimedBump() string {
	return p.head.doc.Predicate.Decision.ClaimedBump
}

// Blast is the head's §6.2 blast-radius score, read from its evidence.blast_radius
// identity ("blast:<score>"). A promotion carries it over unless overridden (§7.3).
func (p *Predecessor) Blast() string {
	return strings.TrimPrefix(p.head.doc.Predicate.Evidence.BlastRadius.ID, "blast:")
}

// Effective is the head's recorded effective trust level (§6.1) — the decision the
// verified accepted chain head attests. A consumer that wants the verified head's
// trust (a release badge, say) reads it from HERE, the freshly-verified object, not
// from an unverified store blob (the attestation store is not a trust anchor, §8.2).
func (p *Predecessor) Effective() string {
	return p.head.doc.Predicate.Trust.Effective
}

// To is the head's release-target commit (the recurring interval's P).
func (p *Predecessor) To() string { return p.head.to }

// Tag is the head's emitted tag name.
func (p *Predecessor) Tag() string { return p.head.tag }

// AttestationDigest is the SHA-256 of the head's DSSE envelope as "sha256:<hex>"
// — the cryptographic identity of the predecessor attestation a recurring release
// binds (§8.1/ADR-027: the successor MUST bind its predecessor attestation's
// identity).
func (p *Predecessor) AttestationDigest() string {
	sum := sha256.Sum256(p.head.envelope)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// AttestationRef is the head attestation's stable store reference
// (refs/attestations/<to>/<content-digest>) — the id a recurring release names as
// its predecessor_attestation.
func (p *Predecessor) AttestationRef() string {
	return attest.EnvelopeRef(p.head.to, p.head.envelope)
}

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
		VersionState versionStateDoc `json:"version_state"`
		Trust        struct {
			Effective string `json:"effective"`
		} `json:"trust"`
		Evidence struct {
			BlastRadius objectIdentity `json:"blast_radius"`
		} `json:"evidence"`
		Decision struct {
			ClaimedBump string          `json:"claimed_bump"`
			Supersedes  *objectIdentity `json:"supersedes"`
		} `json:"decision"`
	} `json:"predicate"`
}

// versionStateDoc is the release/v0.2 version_state wire block.
type versionStateDoc struct {
	Action                 string           `json:"action"`
	Genesis                bool             `json:"genesis"`
	Predecessor            *tagIdentity     `json:"predecessor"`
	PriorState             *stateIdentity   `json:"prior_state"`
	ResultingState         stateIdentity    `json:"resulting_state"`
	TargetCore             string           `json:"target_core"`
	TargetBump             string           `json:"target_bump"`
	Emission               tagEmission      `json:"emission"`
	TargetLineage          []objectIdentity `json:"target_lineage"`
	Iteration              *int             `json:"iteration"`
	PendingCorrectiveFloor *string          `json:"pending_corrective_floor"`
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
	ID     string            `json:"id"`
	Digest map[string]string `json:"digest,omitempty"`
}
