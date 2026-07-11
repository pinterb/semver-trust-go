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
	// (root..TO, §5.2, §10 step 2).
	From string
	// To is the proposed release commit (revision), default "HEAD".
	To string
	// PolicyPath is the policy file's path within TO's tree (§10 step 1).
	PolicyPath string
	// AllowedSignersPath is a filesystem override for the human allowed-signers
	// registry. Empty resolves the policy's identity.human.allowed_signers path
	// from TO's tree.
	AllowedSignersPath string
	// AttestationSignersPath is a filesystem path to the attestation-signer
	// registry. Empty means review attestations cannot be verified: reviews
	// classify none (honest degradation, §4.3) — but a stored attestation that
	// fails verification still aborts.
	AttestationSignersPath string
	// GPGKeyringPath is a filesystem path to an armored OpenPGP public
	// keyring (the CLI --gpg-keyring). Empty means the GPG key family is not
	// verifiable and PGP-signed commits abort as unsupported (fail closed,
	// fixture plan §2.1). Flag-only for now: the §9 policy vocabulary has no
	// identity.human field for a GPG keyring — adding one is a spec-repo
	// question, so no in-tree resolution happens here.
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

	keyring, err := resolvePGPKeyring(opts.GPGKeyringPath)
	if err != nil {
		return nil, abort(stepLoadPolicy, err)
	}
	signers, err := resolveHumanSigners(opts, pol, repo, keyring != nil)
	if err != nil {
		return nil, abort(stepLoadPolicy, err)
	}
	trusted := vcs.TrustedSigners{AllowedSigners: signers, PGPKeyring: keyring}
	attVerifier, err := buildAttestationVerifier(opts.AttestationSignersPath)
	if err != nil {
		return nil, abort(stepLoadPolicy, err)
	}

	// ---- §10 step 2: enumerate commits (root..TO for a first release). -----
	commits, err := vcs.Range(repo, opts.From, opts.To)
	if err != nil {
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

		reviewFacts, reviewNote, err := resolveReview(store, attVerifier, c.Hash, vs.Principal, at)
		if err != nil {
			return nil, abort(stepAttestation, err)
		}

		authorship, review, level := trust.Classify(trust.CommitFacts{
			Signer:           signerClass,
			Provenance:       c.Trailers.Provenance(),
			TrailersRequired: pol.TrailersRequired,
			Review:           reviewFacts,
		})

		tcommits = append(tcommits, trust.Commit{ID: c.Hash, Level: level, Paths: c.Paths})
		report.Commits = append(report.Commits, CommitReport{
			SHA:         c.Hash,
			Short:       shortSHA(c.Hash),
			Level:       level.String(),
			Authorship:  authorship.String(),
			Review:      review.String(),
			Signer:      vs.Principal,
			Fingerprint: vs.Fingerprint,
			Provenance:  c.Trailers.Provenance(),
			Merge:       c.Merge,
			Paths:       c.Paths,
			ReviewNote:  reviewNote,
		})
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

// resolvePGPKeyring loads the injected OpenPGP public keyring, or nil when no
// path was given — the GPG family then stays fail-closed unsupported.
func resolvePGPKeyring(path string) (*vcs.PGPKeyring, error) {
	if path == "" {
		return nil, nil
	}
	data, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("gpg-keyring: %w", err)
	}
	keyring, err := vcs.ParsePGPKeyring(data)
	if err != nil {
		return nil, fmt.Errorf("gpg-keyring: %w", err)
	}
	return keyring, nil
}

// buildAttestationVerifier constructs the review-attestation verifier from the
// injected attestation-signer registry and the vendored predicate schemas, or
// returns nil when no registry was given (reviews then classify none, §4.3).
func buildAttestationVerifier(signersPath string) (*attest.Verifier, error) {
	if signersPath == "" {
		return nil, nil
	}
	data, err := readFile(signersPath)
	if err != nil {
		return nil, fmt.Errorf("attestation-signers: %w", err)
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
