// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"fmt"
	"time"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
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
}

// The §10 step labels an AbortError names. The abort reason the CLI prints to
// stderr carries one of these, so a failure is traceable to the algorithm.
const (
	stepLoadPolicy   = "§10 step 1 (load policy)"
	stepMetaPath     = "§10 step 1 (§5.4 meta-path level)"
	stepEnumerate    = "§10 step 2 (enumerate commits)"
	stepSignature    = "§10 step 3 (verify signature)"
	stepAttestation  = "§10 step 3 (verify review attestation)"
	stepDerivation   = "§10 step 4 (derivation proof)"
	stepPropagate    = "§10 step 6 (propagate)"
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

	// ---- §10 step 2: enumerate commits (root..TO for a first release, ------
	// boundary..TO under a policy-declared adoption boundary, ADR-026). ------
	// Pre-boundary commits are outside the range and contribute nothing: no
	// levels, no scopes — exempt history makes no claim (never T0, ADR-008).
	// An explicit FROM makes the boundary irrelevant: ranges anchored at a
	// previous verified tag are unaffected.
	from := opts.From
	if from == "" && pol.AdoptionBoundary != "" {
		boundarySHA, err := commitHash(repo, pol.AdoptionBoundary)
		if err != nil {
			return nil, abort(stepEnumerate, fmt.Errorf(
				"adoption boundary %q declared in policy ([policy] adoption_boundary, ADR-026) does not resolve: %w",
				pol.AdoptionBoundary, err))
		}
		from = pol.AdoptionBoundary
		// Disclosure (ADR-026): "verified since the boundary" is a different
		// claim from "verified since inception" and must never be conflated —
		// the report marks the boundary in both renderings.
		report.From = pol.AdoptionBoundary
		report.FromIsAdoptionBoundary = true
		report.AdoptionBoundary = boundarySHA
	}
	commits, err := vcs.Range(repo, from, opts.To)
	if err != nil {
		if report.FromIsAdoptionBoundary {
			// vcs.Range enforces FROM-is-an-ancestor-of-TO (§10.2); name the
			// boundary's policy provenance so the abort is traceable.
			err = fmt.Errorf("adoption boundary %q declared in policy ([policy] adoption_boundary, ADR-026): %w",
				pol.AdoptionBoundary, err)
		}
		return nil, abort(stepEnumerate, err)
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

		review, err := resolveReview(store, attVerifier, c.Hash, vs.Principal, at)
		if err != nil {
			return nil, abort(stepAttestation, err)
		}

		authorship, reviewClass, level := trust.Classify(trust.CommitFacts{
			Signer:           signerClass,
			Provenance:       c.Trailers.Provenance(),
			TrailersRequired: pol.TrailersRequired,
			Review:           review.facts,
		})

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
			ReviewNote:  review.note,
		}
		if review.facts != nil {
			row.ReviewIdentity = review.facts.ReviewerIdentity
			row.ReviewAttestation = review.ref
		}
		tcommits = append(tcommits, trust.Commit{ID: c.Hash, Level: level, Paths: c.Paths})
		report.Commits = append(report.Commits, row)
	}

	// ---- §10 step 4: derivation proofs (re-level verified outputs). --------
	report.Derivations, err = runDerivations(repo, opts.To, pol.Derivations, tcommits)
	if err != nil {
		return nil, err
	}
	// Reflect the re-leveling rule name onto each commit's report row.
	for i := range tcommits {
		if d := tcommits[i].Derivation; d != nil && d.Verified {
			report.Commits[i].Derivation = derivationRuleFor(pol.Derivations, d.Outputs)
		}
	}

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

	// ---- §10 step 7: collect evidence, compute the semantic floor. ---------
	report.Evidence, err = collectEvidence(repo, opts, pol, commits)
	if err != nil {
		return nil, err
	}

	return report, nil
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
	return attest.NewVerifier(signers, map[string][]byte{
		attest.PredicateRelease: releaseSchema,
		attest.PredicateReview:  reviewSchema,
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
