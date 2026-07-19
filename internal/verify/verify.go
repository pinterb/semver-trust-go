// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/chain"
	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/trust"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// Options are the inputs to a verification run. Every clock-dependent value is
// injected: VerifyTime flows from the CLI boundary into every internal call so
// nothing under internal/ reads the wall clock (ADR-018).
type Options struct {
	// RepoPath is the repository to verify (the CLI --repo, default ".").
	RepoPath string
	// From is the previous release tag; empty means a first release
	// (root..TO, §5.2, §10 step 2) — unless the policy declares an adoption
	// boundary, in which case a first release anchors at boundary..TO
	// (ADR-026). An explicit From always wins: ranges anchored at a previous
	// verified tag are unaffected by the boundary. There is deliberately no
	// boundary option here — the boundary is policy-pinned (ADR-026 rejects
	// CLI-supplied boundaries: whoever runs the verifier could move it).
	From string
	// To is the proposed release commit (revision), default "HEAD".
	To string
	// PolicyPath is the policy file's path within TO's tree (§10 step 1).
	PolicyPath string
	// AllowedSignersPath is a filesystem override for the human allowed-signers
	// registry. Empty resolves the policy's identity.human.allowed_signers path
	// from TO's tree.
	AllowedSignersPath string
	// AttestationSignersPath is a filesystem override for the attestation-signer
	// registry. Empty resolves the policy's [identity] attestation_signers path
	// from TO's tree (§9, ADR-022); if the policy declares none either, review
	// attestations cannot be verified and classify none (honest degradation,
	// §4.3) — but a stored attestation that fails verification still aborts.
	AttestationSignersPath string
	// GPGKeyringPath is a filesystem override for the armored OpenPGP public
	// keyring (the CLI --gpg-keyring). Empty resolves the policy's
	// [identity.human] gpg_keyring path from TO's tree (§9); if the policy
	// declares none either, the GPG key family is not verifiable and PGP-signed
	// commits abort as unsupported (fail closed, fixture plan §2.1).
	GPGKeyringPath string
	// Component selects which workspace component to headline in propagation
	// output; empty is the single/root component.
	Component string
	// VerifyTime is the verification instant (§10, ADR-018), injected from the
	// CLI boundary.
	VerifyTime time.Time
	// Bootstrap is the authenticated out-of-band bootstrap descriptor
	// (§5.4/§7.5, ADR-028/029). When non-nil the run is in v0.10 mode: step-2
	// enumeration uses the ADR-027 exact interval (vcs.SelectInterval) instead
	// of the two-dot FROM..TO walk, and From is not consulted for the version
	// line. It is loaded and authenticated at the CLI boundary. Nil = the v0.3
	// FROM / policy-boundary path, unchanged.
	Bootstrap *chain.BootstrapDescriptor
}

// The §10 step labels an AbortError names. The abort reason the CLI prints to
// stderr carries one of these, so a failure is traceable to the algorithm.
const (
	stepLoadPolicy  = "§10 step 1 (load policy)"
	stepMetaPath    = "§10 step 1 (§5.4 meta-path level)"
	stepTransition  = "§10 step 1 (§5.4 policy transition)"
	stepEnumerate   = "§10 step 2 (enumerate commits)"
	stepSignature   = "§10 step 3 (verify signature)"
	stepAttestation = "§10 step 3 (verify review attestation)"
	stepDerivation  = "§10 step 4 (derivation proof)"
	stepPropagate   = "§10 step 6 (propagate)"
)

// AbortError is a verification abort: a fail-closed stop naming the §10 step
// that failed (§5.2 unverifiable ≠ T0, §5.4 meta-path). The CLI renders it as
// a one-line reason to stderr and exits non-zero.
type AbortError struct {
	Step string
	Err  error
}

func (e *AbortError) Error() string { return fmt.Sprintf("%s: %v", e.Step, e.Err) }
func (e *AbortError) Unwrap() error { return e.Err }

func abort(step string, err error) error { return &AbortError{Step: step, Err: err} }

// Verify runs §10 steps 1–7 against the options and returns a traceable
// report, or an *AbortError on any fail-closed stop.
//
// Step 1 (load policy from TO's tree) lives here; steps 2–7 run in verifyWith,
// which takes the already-parsed policy. The split is a testing seam: pipeline
// tests inject a minimal policy directly against a fixture repository whose
// tree carries no policy file (the signature-abort fixtures), exercising the
// fail-closed steps without a tree read.
func Verify(opts Options) (*Report, error) {
	// ---- §10 step 1: load policy from TO's tree, record its digest. --------
	policyBytes, err := readTreeFile(opts.RepoPath, opts.To, opts.PolicyPath)
	if err != nil {
		return nil, abort(stepLoadPolicy,
			fmt.Errorf("policy file %q not found in %s's tree: %w", opts.PolicyPath, opts.To, err))
	}
	pol, err := policy.Parse(policyBytes)
	if err != nil {
		return nil, abort(stepLoadPolicy, err)
	}
	return verifyWith(opts, pol)
}

// verifyWith runs §10 steps 2–7 against an already-loaded policy.
func verifyWith(opts Options, pol *policy.Policy) (*Report, error) {
	at := opts.VerifyTime
	repo := opts.RepoPath

	report := &Report{
		Repo:       repo,
		From:       opts.From,
		To:         opts.To,
		Component:  opts.Component,
		VerifyTime: at.UTC().Format(time.RFC3339),
	}
	if c, err := commitHash(repo, opts.To); err == nil {
		report.ToCommit = c
	}
	report.Policy = PolicyReport{
		Path:      opts.PolicyPath,
		Digest:    pol.Digest,
		Threshold: pol.Threshold.String(),
		Strategy:  pol.Strategy.String(),
		Adapter:   pol.GraphAdapter,
	}

	// In v0.10 mode the bootstrap descriptor pins the trust material by digest
	// from TO's tree; a filesystem override would let unpinned material verify
	// commits/attestations while the transition only checks the tree bytes it
	// pinned — a key-substitution bypass (§5.4/ADR-028). Reject overrides here,
	// so the material used for verification IS the material the descriptor pins.
	if opts.Bootstrap != nil {
		switch {
		case opts.AllowedSignersPath != "":
			return nil, abort(stepLoadPolicy, errors.New(
				"--allowed-signers overrides the descriptor-pinned trust material; in v0.10 mode trust material is resolved from TO's tree only"))
		case opts.GPGKeyringPath != "":
			return nil, abort(stepLoadPolicy, errors.New(
				"--gpg-keyring overrides the descriptor-pinned trust material; in v0.10 mode trust material is resolved from TO's tree only"))
		case opts.AttestationSignersPath != "":
			return nil, abort(stepLoadPolicy, errors.New(
				"--attestation-signers overrides the descriptor-pinned trust material; in v0.10 mode trust material is resolved from TO's tree only"))
		}
	}

	keyring, err := resolvePGPKeyring(opts, pol, repo)
	if err != nil {
		return nil, abort(stepLoadPolicy, err)
	}
	signers, err := resolveHumanSigners(opts, pol, repo, keyring != nil)
	if err != nil {
		return nil, abort(stepLoadPolicy, err)
	}
	trusted := vcs.TrustedSigners{AllowedSigners: signers, PGPKeyring: keyring}
	attVerifier, err := buildAttestationVerifier(opts, pol, repo)
	if err != nil {
		return nil, abort(stepLoadPolicy, err)
	}

	// v0.10 recurrence (§7.5/ADR-027): discover the accepted chain head for this
	// component. A prior release/v0.2 makes the run RECURRING — the interval
	// anchors at the predecessor (P..TO), the policy transition uses the
	// predecessor authority, and the version line advances from the carried state.
	// Absent a head — or with no attestation verifier to authenticate one — the run
	// stays genesis, exactly as M1–M3. The head is established by fresh
	// verification and unique-head cardinality, never a payload claim.
	if opts.Bootstrap != nil && attVerifier != nil {
		pred, perr := chain.AcceptedChainHead(repo, opts.Bootstrap.Repository, opts.Bootstrap.Component, attVerifier, at)
		if perr != nil {
			return nil, abort(stepLoadPolicy, perr)
		}
		report.Predecessor = pred
	}

	// ---- §10 step 2: enumerate commits (root..TO for a first release, ------
	// boundary..TO under a policy-declared adoption boundary, ADR-026). ------
	// Pre-boundary commits are outside the range and contribute nothing: no
	// levels, no scopes — exempt history makes no claim (never T0, ADR-008).
	// An explicit FROM makes the boundary irrelevant: ranges anchored at a
	// previous verified tag are unaffected.
	var commits []vcs.RangeCommit
	if opts.Bootstrap != nil {
		// v0.10 mode: the exact ADR-027 interval from the authenticated
		// descriptor. The adoption boundary is INCLUDED and itself verified
		// (earliest verifiable commit, not last legacy release); From is not a
		// range anchor here (a caller FROM is refused by SelectInterval).
		commits, err = enumerateInterval(repo, opts, report)
	} else {
		from := opts.From
		if from == "" && pol.AdoptionBoundary != "" {
			boundarySHA, cerr := commitHash(repo, pol.AdoptionBoundary)
			if cerr != nil {
				return nil, abort(stepEnumerate, fmt.Errorf(
					"adoption boundary %q declared in policy ([policy] adoption_boundary, ADR-026) does not resolve: %w",
					pol.AdoptionBoundary, cerr))
			}
			from = pol.AdoptionBoundary
			// Disclosure (ADR-026): "verified since the boundary" is a different
			// claim from "verified since inception" and must never be conflated —
			// the report marks the boundary in both renderings.
			report.From = pol.AdoptionBoundary
			report.FromIsAdoptionBoundary = true
			report.AdoptionBoundary = boundarySHA
		}
		commits, err = vcs.Range(repo, from, opts.To)
		if err != nil && report.FromIsAdoptionBoundary {
			// vcs.Range enforces FROM-is-an-ancestor-of-TO (§10.2); name the
			// boundary's policy provenance so the abort is traceable.
			err = fmt.Errorf("adoption boundary %q declared in policy ([policy] adoption_boundary, ADR-026): %w",
				pol.AdoptionBoundary, err)
		}
		if err != nil {
			err = abort(stepEnumerate, err)
		}
	}
	if err != nil {
		return nil, err
	}

	// ---- §10 step 3: verify each commit end-to-end and classify. -----------
	store := attest.GitRefStore{Path: repo}
	tcommits := make([]trust.Commit, 0, len(commits))
	report.Commits = make([]CommitReport, 0, len(commits))
	for _, c := range commits {
		vs, err := vcs.VerifyCommitSignature(repo, c.Hash, trusted, at)
		if err != nil {
			return nil, abort(stepSignature, err)
		}
		signerClass := identityClass(pol, vs.Principal)

		review, err := resolveReview(store, attVerifier, pol, c.Hash, vs.Principal, at)
		if err != nil {
			return nil, abort(stepAttestation, err)
		}

		authorship, reviewClass, level, qualifyReason := trust.ClassifyWithQualification(trust.CommitFacts{
			Signer:           signerClass,
			Provenance:       c.Trailers.Provenance(),
			TrailersRequired: pol.TrailersRequired,
			Review:           review.facts,
		}, review.qual)

		note := review.note
		if qualifyReason != "" {
			// A consumed review/v0.2 that verified but did not qualify names why,
			// so the honest degradation is visible rather than silent.
			note = "review/v0.2 did not qualify: " + qualifyReason
		}

		row := CommitReport{
			SHA:         c.Hash,
			Short:       shortSHA(c.Hash),
			Level:       level.String(),
			Authorship:  authorship.String(),
			Review:      reviewClass.String(),
			Signer:      vs.Principal,
			Fingerprint: vs.Fingerprint,
			Provenance:  c.Trailers.Provenance(),
			Trailers:    trailersMap(c.Trailers),
			Merge:       c.Merge,
			Paths:       c.Paths,
			ReviewNote:  note,
		}
		if review.facts != nil {
			row.ReviewIdentity = review.facts.ReviewerIdentity
			row.ReviewAttestation = review.ref
		}
		if review.qual != nil {
			row.ReviewIdentity = review.qual.ReviewerActor
			row.ReviewAttestation = review.ref
		}
		tcommits = append(tcommits, trust.Commit{ID: c.Hash, Level: level, Paths: c.Paths})
		report.Commits = append(report.Commits, row)
	}

	// ---- §10 step 4: derivation claims (non-authoritative; never executed,
	// never re-leveled — ADR-033). -------------------------------------------
	report.Derivations = reportDerivations(pol.Derivations)

	// ---- §10 step 1 / §5.4: meta-path level check (needs levels, so run ----
	// after step 3; reported as the step-1/§5.4 abort — see doc.go). ---------
	violations, err := trust.MetaPathViolations(pol.Meta.Paths, pol.Meta.RequiredLevel, tcommits)
	if err != nil {
		return nil, abort(stepMetaPath, err)
	}
	if len(violations) > 0 {
		return nil, abort(stepMetaPath, fmt.Errorf(
			"commits touch a meta-path below required level %s (§5.4 fails outright, not demote): %v",
			pol.Meta.RequiredLevel, violations))
	}
	report.MetaPath = MetaPathReport{
		Paths:         pol.Meta.Paths,
		RequiredLevel: pol.Meta.RequiredLevel.String(),
		Violations:    []string{},
		Passed:        true,
	}

	// ---- §10 step 5: partition by scope, compute own trust. ----------------
	partition, err := trust.PartitionScopes(pol.Scopes, tcommits)
	if err != nil {
		return nil, err
	}
	floors, err := trust.ScopeFloors(pol.Scopes, tcommits)
	if err != nil {
		return nil, err
	}
	report.Scopes = scopeReports(partition, floors)

	// ---- §10 step 6: propagate over the workspace graph. -------------------
	report.Propagation, err = propagate(repo, opts, pol, tcommits, floors)
	if err != nil {
		return nil, err
	}

	// v0.10 subject binding (§5.4): the authenticated descriptor's component
	// MUST be the component actually verified and reported (the propagation
	// target), so the interval authority and the report bind the same component
	// chain. Enforced here — once the target is known — for verify and release
	// alike, not only in the release decision path.
	if opts.Bootstrap != nil {
		comp, ok := targetComponentEffective(report)
		if !ok {
			return nil, abort(stepEnumerate, fmt.Errorf(
				"propagation target %q is not a resolved component", report.Propagation.Target))
		}
		if opts.Bootstrap.Component != comp.Name {
			return nil, abort(stepEnumerate, fmt.Errorf(
				"bootstrap descriptor component %q does not match the verified component %q (§5.4 subject binding)",
				opts.Bootstrap.Component, comp.Name))
		}
		// The genesis policy and its trust material are authenticated against
		// the out-of-band descriptor (§5.4/ADR-028), not trusted for being in
		// TO's tree. Runs here, after classification, because the guardrails
		// consult per-commit levels/signers.
		if err := checkPolicyTransition(opts, pol, report); err != nil {
			return nil, err
		}
	}

	// ---- §10 step 7: collect evidence, compute the semantic floor. ---------
	report.Evidence, err = collectEvidence(repo, opts, pol, commits)
	if err != nil {
		return nil, err
	}

	// Clean-channel eligibility (§6.2/ADR-032): whether the target component's
	// effective trust meets the policy threshold. INFORMATIONAL only — ADR-032
	// places the threshold gate in the release decision (bound for replay), so
	// verify reports the relationship without gating. No abort here.
	if comp, ok := targetComponentEffective(report); ok {
		effective, perr := trust.ParseLevel(comp.Effective)
		if perr != nil {
			return nil, perr
		}
		report.CleanChannel = &CleanChannelReport{
			Effective: comp.Effective,
			Threshold: pol.Threshold.String(),
			Met:       effective >= pol.Threshold,
		}
	}

	return report, nil
}

// targetComponentEffective returns the propagation row of the headline target
// component and whether it was present in the propagation output.
func targetComponentEffective(report *Report) (ComponentEffective, bool) {
	for _, c := range report.Propagation.Components {
		if c.Name == report.Propagation.Target {
			return c, true
		}
	}
	return ComponentEffective{}, false
}

// checkPolicyTransition runs the §5.4/ADR-028 policy transition for a v0.10
// release. GENESIS: the policy at TO is both active and candidate (the bootstrap
// authority governs the first interval as a fixed point), and the descriptor's
// policy facts must all match it. RECURRING (report.Predecessor set): the accepted
// predecessor chain head is the active authority — its digest-pinned policy path,
// digest, trust material, and mandatory workflows govern the interval, and the
// policy at TO is the candidate activated for the NEXT interval. This PR wires the
// UNCHANGED-policy case (active == candidate == policy@TO, the predecessor pins
// must match); a changed policy fails predecessor_policy_mismatch, and the
// two-stage key rotation (active ≠ candidate) defers to a follow-on (#76 M6-C3).
// The per-commit guardrails (unknown_active_signer, under_level_meta_commit) run
// against the classified interval in both modes.
func checkPolicyTransition(opts Options, pol *policy.Policy, report *Report) error {
	desc := opts.Bootstrap
	pred := report.Predecessor
	recurring := pred != nil

	active, err := MetaPolicyFromTree(pol, opts.PolicyPath, opts.RepoPath, opts.To)
	if err != nil {
		return abort(stepTransition, err)
	}
	commits := make([]policy.TransitionCommit, 0, len(report.Commits))
	for _, c := range report.Commits {
		commits = append(commits, policy.TransitionCommit{Signer: c.Signer, Level: c.Level, Paths: c.Paths})
	}

	rangeMode := desc.IntervalMode
	var boundary *string
	authority := "bootstrap"
	authorityIdentity := PolicyDigestDescriptor{URI: "bootstrap:" + desc.Component, Digest: digestSet(desc.Digest())}
	mandatoryPaths := desc.MandatoryMetaPaths
	switch {
	case recurring:
		rangeMode = "recurring"
		authority = "predecessor"
		authorityIdentity = PolicyDigestDescriptor{URI: "predecessor:" + pred.Tag(), Digest: digestSet(pred.AttestationDigest())}
		mandatoryPaths = pred.PolicyPins().MandatoryMetaPaths
	case desc.Boundary != nil:
		oid := desc.Boundary.OID
		boundary = &oid
	}

	in := policy.TransitionInputs{
		Repository:            desc.Repository,
		Component:             desc.Component,
		Authority:             authority,
		RangeMode:             rangeMode,
		Boundary:              boundary,
		VerificationProfile:   desc.VerificationProfile,
		ClockProfile:          desc.ClockProfile,
		VerificationTime:      report.VerifyTime, // RFC3339 Z (verifyWith)
		ProvidedTrustMaterial: active.TrustMaterial,
		Commits:               commits,
	}
	var reason string
	if recurring {
		predPolicy := recurringPredecessorPolicy(pred, active, desc)
		_, _, reason = policy.SelectPolicyTransition(active, active, nil, &predPolicy, in)
	} else {
		bootstrap := desc.PolicyBootstrap()
		_, _, reason = policy.SelectPolicyTransition(active, active, &bootstrap, nil, in)
	}
	if reason != "" {
		return abort(stepTransition, fmt.Errorf(
			"authenticated policy transition refused (%s, §5.4/ADR-028)", reason))
	}

	// Retain the authenticated policy state for the release path (the release/v0.2
	// policy_state block) rather than re-deriving it. The unchanged-policy case is
	// the candidate==active fixed point, so candidate fields stay nil/empty.
	roots := make([]PolicyDigestDescriptor, 0, len(active.TrustMaterial))
	for _, path := range sortedStrings(mapKeys(active.TrustMaterial)) {
		roots = append(roots, PolicyDigestDescriptor{Path: path, Digest: digestSet(active.TrustMaterial[path])})
	}
	workflows := make([]PolicyDigestDescriptor, 0, len(mandatoryPaths))
	for _, path := range mandatoryPaths {
		dg, err := treeFileDigest(opts.RepoPath, opts.To, path)
		if err != nil {
			return abort(stepTransition, fmt.Errorf("mandatory workflow %q: %w", path, err))
		}
		workflows = append(workflows, PolicyDigestDescriptor{Path: path, Digest: digestSet(dg)})
	}
	report.PolicyState = &PolicyStateReport{
		ActivePolicy:        PolicyDigestDescriptor{Path: active.Path, Digest: digestSet(active.Digest)},
		ActiveTrustRoots:    roots,
		CandidateTrustRoots: []PolicyDigestDescriptor{},
		MandatoryWorkflows:  workflows,
		Authority:           authority,
		AuthorityIdentity:   authorityIdentity,
	}
	return nil
}

// recurringPredecessorPolicy assembles the §5.4/ADR-028 predecessor policy
// authority from the accepted chain head's pins (its authenticated active policy
// path/digest, trust-material digests, and mandatory workflows) plus the
// chain-invariant profiles. TrustRoles are a function of the digest-pinned policy
// and are not carried on the wire; for the unchanged-policy transition they equal
// the active policy's roles — the digest and trust-material checks are the teeth
// that authenticate the policy is unchanged, and a changed policy fails them.
func recurringPredecessorPolicy(pred *chain.Predecessor, active policy.MetaPolicy, desc *chain.BootstrapDescriptor) policy.PredecessorPolicy {
	pins := pred.PolicyPins()
	return policy.PredecessorPolicy{
		Accepted:            true,
		ChainHead:           true,
		Repository:          desc.Repository,
		Component:           desc.Component,
		VerificationProfile: desc.VerificationProfile,
		ClockProfile:        desc.ClockProfile,
		PolicyPath:          pins.PolicyPath,
		PolicyDigest:        pins.PolicyDigest,
		TrustMaterial:       pins.TrustMaterial,
		TrustRoles:          active.TrustRoles,
		MandatoryMetaPaths:  pins.MandatoryMetaPaths,
	}
}

// digestSet parses a "sha256:<hex>" digest into the single-entry digest set the
// release/v0.2 digestDescriptor carries. A value without a "<algo>:" prefix maps
// under "sha256" (the trust-material convention, §5.4).
func digestSet(prefixed string) map[string]string {
	if algo, hex, ok := strings.Cut(prefixed, ":"); ok && algo != "" && hex != "" {
		return map[string]string{algo: hex}
	}
	return map[string]string{"sha256": prefixed}
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func sortedStrings(xs []string) []string {
	sort.Strings(xs)
	return xs
}

// enumerateInterval selects the §5.2/ADR-027 exact release interval and
// materializes it as RangeCommits for classification. GENESIS (no accepted chain
// head) uses the descriptor's inception/adoption mode. RECURRING (report.Predecessor
// set) anchors at the accepted predecessor: the interval is Reach(TO) − Reach(P)
// (git rev-list P..TO), with From pinned to P as ADR-027 requires. A caller From is
// otherwise refused (in v0.10 the interval is authenticated, not caller-anchored).
func enumerateInterval(repo string, opts Options, report *Report) ([]vcs.RangeCommit, error) {
	desc := opts.Bootstrap
	graph, err := vcs.CommitGraph(repo, opts.To)
	if err != nil {
		return nil, abort(stepEnumerate, err)
	}
	in := vcs.IntervalInputs{
		Repository:         desc.Repository,
		Component:          desc.Component,
		Mode:               vcs.IntervalMode(desc.IntervalMode),
		To:                 report.ToCommit,
		ExistingChainHeads: 0,
		Boundary:           desc.IntervalBoundary(),
		Commits:            graph,
	}
	if pred := report.Predecessor; pred != nil {
		// Recurring: the accepted head anchors the interval, and the descriptor's
		// genesis mode/boundary are not consulted. SelectInterval requires
		// RequestedFrom == P. A caller --from is NOT silently replaced with P — it is
		// resolved and passed through, so a caller-selected skip to a non-predecessor
		// revision is refused (from_not_predecessor, §5.2/ADR-027); only when the
		// caller gives no --from do we synthesize the accepted-head anchor P.
		ipd := pred.IntervalDescriptor()
		in.Mode = vcs.IntervalRecurring
		in.ExistingChainHeads = 1
		in.Predecessor = &ipd
		in.Boundary = nil
		from := pred.To()
		if opts.From != "" {
			resolved, cerr := commitHash(repo, opts.From)
			if cerr != nil {
				return nil, abort(stepEnumerate, fmt.Errorf("resolving --from %q: %w", opts.From, cerr))
			}
			from = resolved
		}
		in.RequestedFrom = &from
	} else if opts.From != "" {
		f := opts.From
		in.RequestedFrom = &f
	}
	ids, reason := vcs.SelectInterval(in)
	if reason != "" {
		return nil, abort(stepEnumerate, fmt.Errorf(
			"authenticated release interval refused (%s, §5.2/ADR-027)", reason))
	}
	commits, err := vcs.IntervalCommits(repo, ids)
	if err != nil {
		return nil, abort(stepEnumerate, err)
	}
	// Disclosure. Recurring: anchored at the predecessor tag (not an adoption
	// boundary). Adoption genesis: the bootstrap-pinned boundary is itself INCLUDED
	// and verified (ADR-027/028 — earliest verifiable commit, not last legacy
	// release).
	switch {
	case report.Predecessor != nil:
		report.From = report.Predecessor.Tag()
	case desc.Boundary != nil:
		report.From = desc.Boundary.OID
		report.FromIsAdoptionBoundary = true
		report.AdoptionBoundary = desc.Boundary.OID
	}
	return commits, nil
}

// resolveHumanSigners loads the human allowed-signers registry: the filesystem
// override when given, else the policy's identity.human.allowed_signers path
// read from TO's tree (§9, §10 step 1). With no registry from either source
// the run has no trust material and aborts — unless another key family's
// material was injected (haveOtherFamily), in which case the SSH registry is
// simply empty: a pure-GPG run needs no SSH registry, and any SSH-signed
// commit then still aborts as an unknown signer (fail closed, no grant
// added).
func resolveHumanSigners(opts Options, pol *policy.Policy, repo string, haveOtherFamily bool) ([]vcs.AllowedSigner, error) {
	var data []byte
	switch {
	case opts.AllowedSignersPath != "":
		var err error
		data, err = readFile(opts.AllowedSignersPath)
		if err != nil {
			return nil, fmt.Errorf("allowed-signers: %w", err)
		}
	case pol.Identity.Human.AllowedSigners != "":
		var err error
		data, err = readTreeFile(repo, opts.To, pol.Identity.Human.AllowedSigners)
		if err != nil {
			return nil, fmt.Errorf("allowed-signers from tree (%s): %w", pol.Identity.Human.AllowedSigners, err)
		}
	case haveOtherFamily:
		return nil, nil
	default:
		return nil, errors.New(
			"no trust material: policy declares no identity.human.allowed_signers and neither --allowed-signers nor --gpg-keyring was given")
	}
	return vcs.ParseAllowedSigners(data)
}

// resolvePGPKeyring loads the OpenPGP public keyring: the --gpg-keyring
// filesystem override when given, else the policy's [identity.human]
// gpg_keyring path read from TO's tree (§9, §10 step 1), else nil — the GPG
// family then stays fail-closed unsupported. The flag overrides the policy so
// an operator can supply a keyring out-of-band without editing the root of
// trust.
func resolvePGPKeyring(opts Options, pol *policy.Policy, repo string) (*vcs.PGPKeyring, error) {
	var data []byte
	switch {
	case opts.GPGKeyringPath != "":
		var err error
		data, err = readFile(opts.GPGKeyringPath)
		if err != nil {
			return nil, fmt.Errorf("gpg-keyring: %w", err)
		}
	case pol.Identity.Human.GPGKeyring != "":
		var err error
		data, err = readTreeFile(repo, opts.To, pol.Identity.Human.GPGKeyring)
		if err != nil {
			return nil, fmt.Errorf("gpg-keyring from tree (%s): %w", pol.Identity.Human.GPGKeyring, err)
		}
	default:
		return nil, nil
	}
	keyring, err := vcs.ParsePGPKeyring(data)
	if err != nil {
		return nil, fmt.Errorf("gpg-keyring: %w", err)
	}
	return keyring, nil
}

// buildAttestationVerifier constructs the review-attestation verifier from the
// attestation-signer registry — the --attestation-signers filesystem override
// when given, else the policy's [identity] attestation_signers path read from
// TO's tree (§9, ADR-022, §10 step 1) — and the vendored predicate schemas, or
// returns nil when neither source names one (reviews then classify none, §4.3).
// The flag overrides the policy.
func buildAttestationVerifier(opts Options, pol *policy.Policy, repo string) (*attest.Verifier, error) {
	var data []byte
	switch {
	case opts.AttestationSignersPath != "":
		var err error
		data, err = readFile(opts.AttestationSignersPath)
		if err != nil {
			return nil, fmt.Errorf("attestation-signers: %w", err)
		}
	case pol.Identity.AttestationSigners != "":
		var err error
		data, err = readTreeFile(repo, opts.To, pol.Identity.AttestationSigners)
		if err != nil {
			return nil, fmt.Errorf("attestation-signers from tree (%s): %w", pol.Identity.AttestationSigners, err)
		}
	default:
		return nil, nil
	}
	// The allowed-signers format and its parsed type are shared across commit
	// and attestation verification (internal/sshsig); the namespace column
	// binds each enrollment to its purpose (§8.2).
	signers, err := vcs.ParseAllowedSigners(data)
	if err != nil {
		return nil, fmt.Errorf("attestation-signers: %w", err)
	}
	releaseSchema, err := conformance.Vector("schemas/release-v0.1.json")
	if err != nil {
		return nil, err
	}
	reviewSchema, err := conformance.Vector("schemas/review-v0.1.json")
	if err != nil {
		return nil, err
	}
	// review/v0.2 and release/v0.2 are registered so a stored v0.10 attestation
	// verifies (the qualified review via QualifyReview; the release/v0.2 as the
	// authenticated chain head #76 M6 emits) instead of failing closed as an
	// unsupported predicate.
	reviewV02Schema, err := conformance.Vector("schemas/review-v0.2.json")
	if err != nil {
		return nil, err
	}
	releaseV02Schema, err := conformance.Vector("schemas/release-v0.2.json")
	if err != nil {
		return nil, err
	}
	return attest.NewVerifier(signers, map[string][]byte{
		attest.PredicateRelease:    releaseSchema,
		attest.PredicateReview:     reviewSchema,
		attest.PredicateReviewV02:  reviewV02Schema,
		attest.PredicateReleaseV02: releaseV02Schema,
	})
}

// identityClass maps a verified signer principal to its class (§4.2): a
// principal listed in policy identity.agent.bot_accounts is an agent identity;
// every other registry principal defaults to human. The provenance trailer
// then refines authorship in trust.Classify — a `Provenance: agent` trailer
// concedes agent authorship under any signer (§4.1), so a bot need not be
// enumerated to be classified as one.
func identityClass(pol *policy.Policy, principal string) trust.IdentityClass {
	for _, bot := range pol.Identity.Agent.BotAccounts {
		if bot == principal {
			return trust.IdentityAgent
		}
	}
	return trust.IdentityHuman
}

// trailersMap flattens a commit's trailer block into the map shape the §8.1
// provenance vector carries. Trailers are advisory (§4.1); on a duplicated
// key the first value wins, matching Trailers.Get.
func trailersMap(ts vcs.Trailers) map[string]string {
	if len(ts) == 0 {
		return nil
	}
	m := make(map[string]string, len(ts))
	for _, t := range ts {
		if _, ok := m[t.Key]; !ok {
			m[t.Key] = t.Value
		}
	}
	return m
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func commitHash(repoPath, rev string) (string, error) {
	r, err := openRepo(repoPath)
	if err != nil {
		return "", err
	}
	c, err := resolveCommit(r, rev)
	if err != nil {
		return "", err
	}
	return c.Hash.String(), nil
}
