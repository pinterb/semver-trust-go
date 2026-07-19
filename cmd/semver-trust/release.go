// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/evidence"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/chain"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/trust"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
	"github.com/semver-trust/semver-trust-go/internal/verify"
	"github.com/semver-trust/semver-trust-go/internal/version"
)

// newReleaseCmd is the `release` subcommand: spec §10 end to end. It runs the
// full verify pipeline (steps 1–7), decides channel and version (step 8), and
// emits — a signed annotated tag plus a signed, stored release attestation
// (step 9). Any verification abort refuses the release outright, including
// the §5.4 meta-path failure: the configuration is the root of trust.
func newReleaseCmd() *cobra.Command {
	var (
		// The verify surface, unchanged (steps 1–7 are the same pipeline).
		repoPath            string
		from                string
		to                  string
		policyPath          string
		allowedSigners      string
		attestationSigners  string
		gpgKeyring          string
		component           string
		verifyTime          string
		bootstrapDescriptor string
		jsonOut             bool

		// The release surface (steps 8–9).
		claimedBump string
		blast       string
		iteration   uint64
		tagKeyPath  string
		attKeyPath  string
		taggerName  string
		taggerEmail string
		dryRun      bool

		// The v0.2 emission surface (§8.1/ADR-030; opt-in, requires a descriptor).
		predicate        string
		repositoryDigest string
		action           string
	)

	cmd := &cobra.Command{
		Use:   "release",
		Short: "Evaluate, decide, and emit a release: signed tag + release attestation (spec §10 steps 8-9)",
		Long: `release runs the complete §10 verification algorithm. Steps 1-7 are exactly
what verify runs — and ANY abort there refuses the release, including a policy
file that fails the §5.4 meta-path level: the configuration is the root of
trust, so a policy whose own history cannot be trusted decides nothing.

Step 8 decides: the semantic floor (§6.1, differ-derived when the policy
configures one and FROM resolves, declared intent otherwise) is honored
unconditionally; the §6.4 decision table maps effective trust × blast to the
clean or pre-release channel, degrading honestly where a required differ
proof is unavailable.

Step 9 emits: an SSH-signed annotated tag (SSHSIG in git's own signature
namespace, so 'git tag -v' verifies it against an allowed-signers file) and a
release attestation — an in-toto Statement under the frozen predicate type,
schema-validated against release-v0.1.json BEFORE signing, signed per ADR-022,
self-verified before output, and stored under refs/attestations/... for both
the release commit and the tag name.

The blast-radius score is operator-supplied in v1 (--blast) and recorded as
such in the attestation's evidence.blast_radius.inputs: the spec's §6.2
mapping is deliberately non-numeric, and an honest "the operator judged this
low" beats a fabricated formula (§1.1). --dry-run evaluates and decides, then
prints the would-be tag and attestation without writing anything.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The clock is read once, here at the process boundary, and
			// injected everywhere (ADR-018): verification instant, decision
			// timestamp, and tagger date are the same instant.
			at := time.Now()
			if verifyTime != "" {
				parsed, err := time.Parse(time.RFC3339, verifyTime)
				if err != nil {
					return err
				}
				at = parsed
			}
			claimed, err := evidence.ParseBump(claimedBump)
			if err != nil {
				return fmt.Errorf("--claimed-bump: %w", err)
			}
			blastScore, err := trust.ParseBlast(blast)
			if err != nil {
				return fmt.Errorf("--blast: %w", err)
			}
			// In v0.10 mode the iteration is authenticated by the version
			// ancestry (§7.5); a caller-selected iteration override is refused
			// (§10 forbids caller-selected protocol state).
			if bootstrapDescriptor != "" && cmd.Flags().Changed("iteration") {
				return errors.New("release refused: --iteration is not consulted with --bootstrap-descriptor; the iteration is authenticated by the version ancestry (§7.5/ADR-029)")
			}
			// Load the out-of-band descriptor once (the v0.10 opt-in): it
			// governs both the exact ADR-027 interval (verify step 2) and the
			// §7.5 version line (step 8).
			var desc *chain.BootstrapDescriptor
			if bootstrapDescriptor != "" {
				desc, err = chain.LoadBootstrapDescriptor(bootstrapDescriptor, repoPath)
				if err != nil {
					return fmt.Errorf("release refused: %w", err)
				}
			}

			// The predicate selects the emitted attestation shape. release/v0.2 is
			// the v0.10 authenticated chain head (§8.1/ADR-030): it binds the
			// digest-pinned policy state and the ADR-036 version state, which only
			// exist in v0.10 mode — so it requires the bootstrap descriptor, and its
			// §4.3 repository identity requires an operator-supplied digest.
			var repoDigest map[string]string
			switch predicate {
			case "", "v0.1":
				predicate = "v0.1"
			case "v0.2":
				if desc == nil {
					return errors.New("release refused: --predicate v0.2 requires --bootstrap-descriptor (the authenticated v0.10 chain; §8.1/ADR-030)")
				}
				repoDigest, err = parseRepositoryDigest(repositoryDigest)
				if err != nil {
					return fmt.Errorf("release refused: %w", err)
				}
			default:
				return fmt.Errorf("--predicate: unknown value %q (want v0.1 or v0.2)", predicate)
			}

			// The version action (§7.5/ADR-029) is a signed release-decision fact.
			// recut re-cuts an unpromoted prerelease target and is only meaningful
			// on the authenticated v0.10 chain (it needs an accepted prerelease
			// predecessor, checked at decide time).
			switch action {
			case "", "advance":
				action = "advance"
			case "recut":
				if desc == nil {
					return errors.New("release refused: --action recut requires --bootstrap-descriptor (it re-cuts an accepted prerelease predecessor, §7.5/ADR-029)")
				}
				if predicate != "v0.2" {
					return errors.New("release refused: --action recut requires --predicate v0.2; the recut is a §7.5 version-state fact only the release/v0.2 predicate binds (a v0.1 release cannot represent it in the accepted chain)")
				}
			default:
				return fmt.Errorf("--action: unknown value %q (want advance or recut)", action)
			}

			// Signing material resolves before any evaluation so a missing
			// key fails fast, not after a half-done pipeline. --dry-run
			// writes nothing and therefore needs no keys.
			var tagSigner, attSigner ssh.Signer
			if !dryRun {
				if tagKeyPath == "" || attKeyPath == "" {
					return errors.New("release signs a tag and an attestation: --tag-key and --attest-key are required (or use --dry-run)")
				}
				if tagSigner, err = loadSignerFile(tagKeyPath, "--tag-key"); err != nil {
					return err
				}
				if attSigner, err = loadSignerFile(attKeyPath, "--attest-key"); err != nil {
					return err
				}
				if taggerName == "" || taggerEmail == "" {
					taggerName, taggerEmail, err = vcs.Tagger(repoPath)
					if err != nil {
						return fmt.Errorf("resolving tagger identity (pass --tagger-name/--tagger-email): %w", err)
					}
				}
			}

			// ---- §10 steps 1-7: the verify pipeline; any abort refuses. ----
			report, err := verify.Verify(verify.Options{
				RepoPath:               repoPath,
				From:                   from,
				To:                     to,
				PolicyPath:             policyPath,
				AllowedSignersPath:     allowedSigners,
				AttestationSignersPath: attestationSigners,
				GPGKeyringPath:         gpgKeyring,
				Component:              component,
				VerifyTime:             at,
				Bootstrap:              desc,
			})
			if err != nil {
				return fmt.Errorf("release refused: %w", err)
			}

			// ---- §10 step 8: decide channel and version. -------------------
			// When an out-of-band bootstrap descriptor is supplied the run is in
			// v0.10 mode: the version line is authenticated against the real
			// commit graph via §7.5 ancestry, independent of --from (go#70).
			var (
				decision           trust.Decision
				comp               verify.ComponentEffective
				versionPredecessor *string
				vdec               *versionDecision // v0.10 version authority; nil in the v0.3 path
			)
			if desc != nil {
				vd, derr := decideReleaseAncestry(report, desc, repoPath, claimed, blastScore, action)
				if derr != nil {
					return derr
				}
				vdec = &vd
				decision, comp, versionPredecessor, iteration = vd.Decision, vd.Component, vd.Predecessor, vd.Iteration
				// Bind the emitted predicate's component to the version authority:
				// the descriptor is the component of record.
				component = desc.Component
			} else {
				decision, comp, err = decideRelease(report, from, component, claimed, blastScore, iteration)
				if err != nil {
					return err
				}
			}
			tagName := decision.Version.String()

			// Refuse to move an existing tag before anything is signed: a
			// re-cut at the same core version and level is a new iteration
			// (§7.2), never a replaced ref.
			if exists, err := vcs.TagExists(repoPath, tagName); err != nil {
				return err
			} else if exists {
				return fmt.Errorf("release refused: %w: %s (a re-cut increments the trust-suffix iteration, §7.2)",
					vcs.ErrTagExists, tagName)
			}

			result := releaseResult{
				DryRun:               dryRun,
				Channel:              decision.Channel.String(),
				Version:              decision.Version.String(),
				Tag:                  tagName,
				ToCommit:             report.ToCommit,
				Bump:                 decision.Bump.String(),
				ClaimedBump:          claimed.String(),
				SemanticFloor:        report.Evidence.SemanticFloor,
				Effective:            comp.Effective,
				Own:                  comp.Own,
				Blast:                blast,
				Strategy:             report.Policy.Strategy,
				Iteration:            iteration,
				VersionAuthenticated: bootstrapDescriptor != "",
				VersionPredecessor:   versionPredecessor,
				PredicateType:        attest.PredicateRelease,
				Report:               report,
			}

			// ---- §10 step 9: emit. Two predicate arms. -------------------------
			// The v0.2 arm (ADR-030) binds version_state.emission.tag to the signed
			// tag object's raw ref OID, which exists only after the tag is created,
			// and signed bytes are frozen — so it REORDERS to create the tag first.
			// The v0.1 arm keeps the classic build-sign-then-tag order.
			if predicate == "v0.2" {
				result.PredicateType = attest.PredicateReleaseV02
				v02, err := releaseV02Input(report, comp, decision, *vdec, desc, claimed, blast, repoDigest, tagName, at)
				if err != nil {
					return err
				}
				if dryRun {
					// Preview: no tag is created, so emission.tag stays null.
					payload, err := attest.BuildReleaseV02Statement(v02)
					if err != nil {
						return err
					}
					return result.render(cmd, jsonOut, payload)
				}
				releaseSchema, err := conformance.Vector("schemas/release-v0.2.json")
				if err != nil {
					return err
				}
				emitter, err := attest.NewReleaseV02Emitter(attSigner, releaseSchema)
				if err != nil {
					return err
				}
				// Create the tag first (ADR-036: resulting_state.digest excludes
				// emission, so it is already stable), then bind its OIDs into the
				// emission block before signing. An Emit failure best-effort deletes
				// the tag: an orphan tag carries no release attestation, and verify
				// never trusts a tag without one.
				message := fmt.Sprintf("%s\n\nSemVer-Trust release: channel %s, effective trust %s, claimed bump %s.\n",
					tagName, decision.Channel, comp.Effective, claimed)
				if err := vcs.CreateSignedTag(repoPath, tagName, report.ToCommit, taggerName, taggerEmail, message, at, tagSigner); err != nil {
					return err
				}
				peeled, err := vcs.TagRefs(repoPath)
				if err != nil {
					_ = vcs.DeleteTag(repoPath, tagName)
					return err
				}
				ref, ok := peeled[tagName]
				if !ok {
					_ = vcs.DeleteTag(repoPath, tagName)
					return fmt.Errorf("release refused: created tag %q is absent from the ref-set; cannot bind version_state.emission", tagName)
				}
				v02.VersionState.Emission.Tag = &attest.ReleaseTagIdentity{
					Name:            tagName,
					RawRefOID:       ref.RefOID,
					PeeledCommitOID: ref.CommitOID,
				}
				emission, err := emitter.Emit(v02)
				if err != nil {
					_ = vcs.DeleteTag(repoPath, tagName)
					return err
				}
				// StoreForSubjects writes subjects sequentially and returns the refs
				// written before any error. Because the tag was created BEFORE the
				// store (the reorder), a partial or failed store must roll the tag
				// back too — a tag with no complete release attestation is exactly
				// the orphan state the reorder exists to prevent. The already-written
				// attestation refs (if any) are inert without the tag, so they are
				// surfaced for the operator to prune or audit rather than deleted.
				refs, err := attest.StoreForSubjects(
					attest.GitRefStore{Path: repoPath}, []string{report.ToCommit, tagName}, emission.Envelope)
				if err != nil {
					_ = vcs.DeleteTag(repoPath, tagName)
					if len(refs) > 0 {
						return fmt.Errorf("release refused: storing the release/v0.2 attestation failed after %d of 2 subjects; the tag was rolled back, prune the partial attestation refs %v: %w",
							len(refs), refs, err)
					}
					return fmt.Errorf("release refused: storing the release/v0.2 attestation failed; the tag was rolled back: %w", err)
				}
				result.Signer = emission.KeyID
				result.StoredRefs = refs
				return result.render(cmd, jsonOut, nil)
			}

			input, err := releaseStatementInput(report, comp, decision, claimed, blast, tagName, component, at)
			if err != nil {
				return err
			}
			if dryRun {
				payload, err := attest.BuildReleaseStatement(input)
				if err != nil {
					return err
				}
				return result.render(cmd, jsonOut, payload)
			}

			// The v0.1 envelope is built, schema-validated, signed, and
			// self-verified BEFORE the tag ref moves, so the only failure mode that
			// can leave a tag without its attestation is a storage write error.
			releaseSchema, err := conformance.Vector("schemas/release-v0.1.json")
			if err != nil {
				return err
			}
			emitter, err := attest.NewReleaseEmitter(attSigner, releaseSchema)
			if err != nil {
				return err
			}
			emission, err := emitter.Emit(input)
			if err != nil {
				return err
			}

			message := fmt.Sprintf("%s\n\nSemVer-Trust release: channel %s, effective trust %s, claimed bump %s.\n",
				tagName, decision.Channel, comp.Effective, claimed)
			if err := vcs.CreateSignedTag(repoPath, tagName, report.ToCommit, taggerName, taggerEmail, message, at, tagSigner); err != nil {
				return err
			}

			// Stored under BOTH subjects: a verifier looking the release up
			// by commit or by tag name finds the same envelope (§8.2).
			refs, err := attest.StoreForSubjects(
				attest.GitRefStore{Path: repoPath}, []string{report.ToCommit, tagName}, emission.Envelope)
			if err != nil {
				return err
			}
			result.Signer = emission.KeyID
			result.StoredRefs = refs
			return result.render(cmd, jsonOut, nil)
		},
	}

	f := cmd.Flags()
	f.StringVar(&repoPath, "repo", ".", "repository to release from")
	f.StringVar(&from, "from", "", "previous release tag; empty = first release (root..TO, or boundary..TO under a policy-declared adoption_boundary, ADR-026)")
	f.StringVar(&to, "to", "HEAD", "proposed release commit (revision)")
	f.StringVar(&policyPath, "policy", ".semver-trust/policy.toml", "policy file path within TO's tree")
	f.StringVar(&allowedSigners, "allowed-signers", "", "filesystem allowed-signers override; empty resolves the policy's identity.human.allowed_signers from TO's tree")
	f.StringVar(&attestationSigners, "attestation-signers", "", "filesystem attestation-signer registry; overrides the policy. Empty resolves [identity] attestation_signers from TO's tree (§9); if the policy declares none either, reviews cannot be verified and classify none")
	f.StringVar(&gpgKeyring, "gpg-keyring", "", "armored OpenPGP public keyring for GPG-signed commits; overrides the policy. Empty resolves [identity.human] gpg_keyring from TO's tree (§9); if the policy declares none either, the GPG key family is unverifiable and fails closed")
	f.StringVar(&component, "component", "", "component to release (tag prefix and attestation component); empty = the single/root component")
	f.StringVar(&verifyTime, "verify-time", "", "verification instant (RFC3339); empty = now at the CLI boundary")
	f.StringVar(&bootstrapDescriptor, "bootstrap-descriptor", "", "out-of-band v0.10 bootstrap descriptor (§5.4/§7.5, ADR-028/029); when supplied, the version line is derived from the authenticated descriptor rather than --from. Must be supplied from outside the repository")
	f.BoolVar(&jsonOut, "json", false, "emit a structured JSON result instead of the human summary")
	f.StringVar(&claimedBump, "claimed-bump", "", "the bump this release claims: patch|minor|major (required)")
	f.StringVar(&blast, "blast", "", "operator-supplied §6.2 blast-radius score: low|moderate|high (required; recorded as operator-supplied in the attestation)")
	f.Uint64Var(&iteration, "iteration", 1, "trust-suffix iteration for a pre-release cut (§7.2 re-cuts increment it)")
	f.StringVar(&tagKeyPath, "tag-key", "", "OpenSSH private key signing the tag (git namespace)")
	f.StringVar(&attKeyPath, "attest-key", "", "OpenSSH private key signing the release attestation (attestation namespace; may equal --tag-key)")
	f.StringVar(&taggerName, "tagger-name", "", "tagger name; empty resolves git config user.name")
	f.StringVar(&taggerEmail, "tagger-email", "", "tagger email; empty resolves git config user.email")
	f.BoolVar(&dryRun, "dry-run", false, "evaluate and decide, print the would-be tag and attestation, write nothing")
	f.StringVar(&predicate, "predicate", "v0.1", "release attestation predicate: v0.1 (default) or v0.2. v0.2 emits the §8.1/ADR-030 authenticated chain head and requires --bootstrap-descriptor and --repository-digest")
	f.StringVar(&repositoryDigest, "repository-digest", "", "canonical repository identity digest (<algo>:<hex>, §4.3) bound into a release/v0.2 attestation; required with --predicate v0.2")
	f.StringVar(&action, "action", "advance", "version action (§7.5/ADR-029): advance (default, a new target core) or recut (re-cut an unpromoted prerelease target — same core, next iteration). recut requires --bootstrap-descriptor and an accepted prerelease predecessor")
	for _, required := range []string{"claimed-bump", "blast"} {
		if err := cmd.MarkFlagRequired(required); err != nil {
			panic(err)
		}
	}
	return cmd
}

// decideRelease assembles the §10 step 8 inputs from the verify report and
// runs trust.Decide: the policy's strategy, the target component's effective
// trust, the step-7 semantic floor and differ availability, and the current
// version derived from FROM. It returns the decision and the component row
// the attestation's trust section reports.
func decideRelease(report *verify.Report, from, component string, claimed evidence.Bump, blast trust.Blast, iteration uint64) (trust.Decision, verify.ComponentEffective, error) {
	strategy, err := trust.ParseStrategy(report.Policy.Strategy)
	if err != nil {
		return trust.Decision{}, verify.ComponentEffective{}, err
	}
	comp, err := targetEffective(report)
	if err != nil {
		return trust.Decision{}, verify.ComponentEffective{}, err
	}
	effective, err := trust.ParseLevel(comp.Effective)
	if err != nil {
		return trust.Decision{}, verify.ComponentEffective{}, err
	}
	floor, err := evidence.ParseBump(report.Evidence.SemanticFloor)
	if err != nil {
		return trust.Decision{}, verify.ComponentEffective{}, err
	}
	current, err := currentVersion(from, component)
	if err != nil {
		return trust.Decision{}, verify.ComponentEffective{}, err
	}

	threshold, err := trust.ParseLevel(report.Policy.Threshold)
	if err != nil {
		return trust.Decision{}, verify.ComponentEffective{}, err
	}

	decision, err := trust.Decide(trust.DecideInputs{
		Effective:       effective,
		Blast:           blast,
		Strategy:        strategy,
		Threshold:       threshold,
		DifferAvailable: report.Evidence.DifferAvailable,
		SemanticFloor:   floor,
		ClaimedBump:     claimed,
		Current:         current,
		Iteration:       iteration,
	})
	if err != nil {
		return trust.Decision{}, verify.ComponentEffective{}, err
	}
	if decision.Escalate {
		// §6.3 leaves the inflate escalation target (MINOR vs MAJOR) a policy
		// choice the spec does not pin; v1 refuses rather than inventing one.
		return trust.Decision{}, verify.ComponentEffective{}, errors.New(
			"release refused: strategy \"inflate\" requires an escalated bump whose target (§6.3: PATCH→MINOR or →MAJOR) v1 does not choose for you; use strategy \"demote\" or release from a state whose evidence supports the claim")
	}
	return decision, comp, nil
}

// targetEffective returns the propagation row of the component being
// released — the effective trust the decision consumes and the attestation
// reports.
func targetEffective(report *verify.Report) (verify.ComponentEffective, error) {
	target := report.Propagation.Target
	for _, c := range report.Propagation.Components {
		if c.Name == target {
			return c, nil
		}
	}
	return verify.ComponentEffective{}, fmt.Errorf(
		"component %q not present in propagation output (adapter %s)", target, report.Propagation.Adapter)
}

// currentVersion derives the version the bump applies to: FROM parsed under
// the §7.1 grammar when given (it must be a clean release tag — trust.Decide
// enforces that), or the v0.0.0 baseline for a first release. The component
// path must be consistent between --component and a component-prefixed FROM.
func currentVersion(from, component string) (version.Version, error) {
	if from == "" {
		return version.Version{Component: component}, nil
	}
	v, err := version.Parse(from)
	if err != nil {
		return version.Version{}, fmt.Errorf("--from must be the previous release tag (§7.1): %w", err)
	}
	switch {
	case v.Component == "":
		v.Component = component
	case component != "" && v.Component != component:
		return version.Version{}, fmt.Errorf(
			"--from component %q conflicts with --component %q", v.Component, component)
	}
	return v, nil
}

// versionDecision is the v0.10 decide result: the channel/version decision, the
// released component's effective row, the authenticated version predecessor tag
// (nil for a descriptor-declared new line), the authenticated iteration, and the
// ADR-036 carried-forward version state the release/v0.2 predicate binds (its
// resulting_state digest and version_state block). The state is fully determined
// by the descriptor, the ancestry result, and the decision — no evaluator change
// is needed to surface it.
type versionDecision struct {
	Decision    trust.Decision
	Component   verify.ComponentEffective
	Predecessor *string
	Iteration   uint64
	State       version.VersionState
	// Action is the signed §7.5 version action (advance | recut). PredecessorTag
	// is the chain predecessor's emitted tag the successor binds as its
	// version_state.predecessor (the chain link) — it equals State.Baseline for
	// genesis and advance, but for recut the canonical baseline is preserved while
	// the chain predecessor is the tag being re-cut, so they differ.
	Action         string
	PredecessorTag *version.Binding
}

// decideReleaseAncestry is the v0.10 decide path (§7.5/ADR-029) used when a
// bootstrap descriptor supplies the authority. It authenticates the version
// line against the real commit graph and ref-set via version.SelectVersionAncestry
// — so a genesis or adoption release continues the authenticated version
// predecessor's line rather than restarting it, and the predecessor and boundary
// are facts of the descriptor, not of --from spelling (go#70). --from and
// --iteration are not consulted: the descriptor is the version authority, and a
// genesis iteration is authenticated (always 1).
func decideReleaseAncestry(report *verify.Report, desc *chain.BootstrapDescriptor, repoPath string, claimed evidence.Bump, blast trust.Blast, action string) (versionDecision, error) {
	fail := func(err error) (versionDecision, error) {
		return versionDecision{}, err
	}
	comp, err := targetEffective(report)
	if err != nil {
		return fail(err)
	}
	// The descriptor is the component authority: its component MUST be the
	// component actually released and attested (the propagation target), so the
	// authenticated version line and the emitted release predicate bind the same
	// component chain (§5.4 subject binding).
	if desc.Component != comp.Name {
		return fail(fmt.Errorf("release refused: bootstrap descriptor component %q does not match the released component %q (§5.4 subject binding)", desc.Component, comp.Name))
	}

	nodes, err := vcs.CommitGraph(repoPath, report.ToCommit)
	if err != nil {
		return fail(err)
	}
	graph := make([]version.AncestryCommit, len(nodes))
	for i, n := range nodes {
		graph[i] = version.AncestryCommit(n)
	}
	peeled, err := vcs.TagRefs(repoPath)
	if err != nil {
		return fail(err)
	}
	refs := make(map[string]version.RefEntry, len(peeled))
	for tag, r := range peeled {
		refs[tag] = version.RefEntry(r)
	}

	decisionInputs := version.DecisionInputs{
		EffectiveTrust:  comp.Effective,
		Threshold:       report.Policy.Threshold,
		Blast:           blast.String(),
		Strategy:        report.Policy.Strategy,
		DifferAvailable: report.Evidence.DifferAvailable,
		SemanticFloor:   report.Evidence.SemanticFloor,
		ClaimedBump:     claimed.String(),
	}

	// GENESIS uses the bootstrap authority; RECURRING (an accepted chain head was
	// discovered by verify) advances the version line from the predecessor's
	// carried state under the predecessor authority (§7.5/ADR-029). The interval
	// mode, authority, and predecessor input differ; the decision inputs are the
	// same.
	pred := report.Predecessor
	if action == "recut" && pred == nil {
		return fail(errors.New("release refused: --action recut needs an accepted prerelease predecessor; none was found for this component (a genesis release advances)"))
	}
	var result version.AncestryResult
	var sel version.VersionSelected
	if pred != nil {
		sel = pred.VersionSelected()
		result = version.SelectVersionAncestry(version.AncestryInputs{
			Authority:    "predecessor",
			Action:       action,
			Repository:   desc.Repository,
			Component:    desc.Component,
			TagPrefix:    desc.TagPrefix,
			IntervalMode: "recurring",
			To:           report.ToCommit,
			Graph:        graph,
			Refs:         refs,
			Decision:     decisionInputs,
			Predecessor:  &sel,
		})
	} else {
		var boundary *string
		if desc.Boundary != nil {
			oid := desc.Boundary.OID
			boundary = &oid
		}
		bootstrap := desc.VersionBootstrap()
		result = version.SelectVersionAncestry(version.AncestryInputs{
			Authority:    "bootstrap",
			Action:       "advance",
			Repository:   desc.Repository,
			Component:    desc.Component,
			TagPrefix:    desc.TagPrefix,
			IntervalMode: desc.IntervalMode,
			Boundary:     boundary,
			To:           report.ToCommit,
			Graph:        graph,
			Refs:         refs,
			Decision:     decisionInputs,
			Bootstrap:    &bootstrap,
		})
	}
	if result.Reason != "" {
		return fail(fmt.Errorf("release refused: authenticated version ancestry failed (%s, §7.5/ADR-029)", result.Reason))
	}
	if result.Version == nil {
		return fail(errors.New("release refused: version ancestry authenticated but produced no version tag"))
	}
	ver, err := version.Parse(*result.Version)
	if err != nil {
		return fail(fmt.Errorf("release refused: version ancestry produced an unparseable tag %q: %w", *result.Version, err))
	}
	channel := trust.ChannelClean
	if ver.Trust != nil {
		channel = trust.ChannelPrerelease
	}
	// The semantic floor is honored unconditionally (§6.1); the effective bump
	// is max(claim, floor). evidence.Bump ranks patch<minor<major by iota.
	bump := claimed
	if floor, ferr := evidence.ParseBump(report.Evidence.SemanticFloor); ferr == nil && floor > bump {
		bump = floor
	}
	// The iteration is authenticated by the ancestry result, never the --iteration
	// flag (rejected in v0.10 mode): a prerelease carries the computed iteration, a
	// clean cut has none — reported as the vestigial 1, matching a clean v0.3 cut.
	iteration := uint64(1)
	if result.Iteration != nil {
		iteration = uint64(*result.Iteration)
	}
	if result.TargetCore == nil {
		return fail(errors.New("release refused: version ancestry authenticated but produced no target core"))
	}

	// Assemble the ADR-036 carried-forward version state the release/v0.2 predicate
	// binds. RECURRING ADVANCE: the predecessor's emitted tag becomes the new
	// baseline, its target core the new baseline core, and the lineage appends the
	// new interval (P..TO) — or starts fresh from a clean predecessor (ADR-029).
	// RECURRING RECUT: the unpromoted target is PRESERVED — baseline, baseline core,
	// and target bump carry unchanged and only the source lineage grows. GENESIS: no
	// prior state; the baseline is the descriptor's version predecessor (nil for a
	// new line) at core 0.0.0, single genesis interval. This object is what
	// version.StateDigest hashes for resulting_state.digest, so a recurring verifier
	// rebuilding it from the same authenticated inputs reproduces it byte-for-byte.
	var baseline *version.Binding
	baselineCore := "0.0.0"
	targetBump := bump.String()
	var lineage []string
	var predecessorTag *version.Binding
	if pred != nil {
		can := sel.CanonicalTags[0]
		chainTag := &version.Binding{Tag: can.Tag, RefOID: can.RefOID, CommitOID: can.CommitOID}
		predecessorTag = chainTag
		intervalID := pred.To() + ".." + report.ToCommit
		if action == "recut" {
			baseline = sel.State.Baseline
			baselineCore = sel.State.BaselineCore
			targetBump = sel.State.TargetBump
			lineage = append(append([]string{}, sel.State.TargetIntervals...), intervalID)
		} else {
			baseline = chainTag
			baselineCore = sel.State.TargetCore
			if sel.State.CleanAccepted {
				lineage = []string{intervalID}
			} else {
				lineage = append(append([]string{}, sel.State.TargetIntervals...), intervalID)
			}
		}
	} else {
		bootstrap := desc.VersionBootstrap()
		if bootstrap.Predecessor != nil {
			baseline = &version.Binding{
				Tag:       bootstrap.Predecessor.Tag,
				RefOID:    bootstrap.Predecessor.RefOID,
				CommitOID: bootstrap.Predecessor.CommitOID,
			}
			if pv, perr := version.Parse(bootstrap.Predecessor.Tag); perr == nil {
				baselineCore = fmt.Sprintf("%d.%d.%d", pv.Major, pv.Minor, pv.Patch)
			}
		}
		predecessorTag = baseline
		lineage = []string{version.GenesisIntervalID(desc.Component, desc.IntervalMode)}
	}
	iterations := map[string]int{}
	if ver.Trust != nil {
		iterations[fmt.Sprintf("T%d", ver.Trust.Level)] = int(ver.Trust.Iteration)
	}
	state := version.VersionState{
		Baseline:        baseline,
		BaselineCore:    baselineCore,
		TargetCore:      *result.TargetCore,
		TargetBump:      targetBump,
		CleanAccepted:   ver.Trust == nil,
		TargetIntervals: lineage,
		Iterations:      iterations,
		CorrectiveFloor: result.CorrectiveFloor,
	}

	return versionDecision{
		Decision:       trust.Decision{Channel: channel, Bump: bump, Version: ver},
		Component:      comp,
		Predecessor:    result.VersionPredecessor,
		Iteration:      iteration,
		State:          state,
		Action:         action,
		PredecessorTag: predecessorTag,
	}, nil
}

// releaseStatementInput maps the verify report and the decision onto the
// §8.1 predicate shape. Judgment calls, all documented and attested rather
// than silently invented:
//
//   - blast_radius is operator-supplied in v1: the score arrives via --blast
//     and inputs records {"source": "operator"} plus the universal git input
//     (changed-file count). LOC/fan-in/coverage need providers not wired in
//     v1 and are absent, never fabricated (§1.1).
//   - floor_source is null when the component floors itself — the schema's
//     documented meaning; the internal FloorSource=self representation maps
//     to null here.
//   - dependencies_pinned pins internal deps at TO's tree state (the commit
//     SHA): v1 workspace propagation evaluates every component at the same
//     tree (cross-range propagation is deferred, §12.4). No graph adapter →
//     empty list (present, per the schema).
//   - supersedes is always null: promotion (§7.3) is out of scope for v1.
func releaseStatementInput(report *verify.Report, comp verify.ComponentEffective, decision trust.Decision,
	claimed evidence.Bump, blast, tagName, componentFlag string, at time.Time) (attest.ReleaseInput, error) {

	componentName := componentFlag
	if componentName == "" {
		componentName = report.Propagation.Target
	}
	if componentName == "" {
		return attest.ReleaseInput{}, errors.New("no component scope to attest (§5.1): empty propagation output")
	}

	commits := make([]attest.ReleaseCommit, 0, len(report.Commits))
	for _, c := range report.Commits {
		// Derivation claims are non-authoritative and never re-level (ADR-033);
		// the optional per-commit derivations field is no longer populated.
		var derivations []string
		commits = append(commits, attest.ReleaseCommit{
			SHA:               c.SHA,
			Level:             c.Level,
			AuthorshipClass:   c.Authorship,
			SignerIdentity:    c.Signer,
			Trailers:          c.Trailers,
			ReviewClass:       predicateReviewClass(c.Review),
			ReviewerIdentity:  c.ReviewIdentity,
			ReviewAttestation: c.ReviewAttestation,
			Derivations:       derivations,
		})
	}

	var floorSource *attest.ComponentVersion
	if comp.FloorSource != comp.Name {
		floorSource = &attest.ComponentVersion{Component: comp.FloorSource, Version: report.ToCommit}
	}
	pinned := make([]attest.ComponentVersion, 0, len(comp.Dependencies))
	for _, dep := range comp.Dependencies {
		pinned = append(pinned, attest.ComponentVersion{Component: dep, Version: report.ToCommit})
	}

	var compat *attest.ReleaseCompat
	if report.Evidence.DifferAvailable {
		compat = &attest.ReleaseCompat{
			Provider: report.Evidence.DifferProvider,
			Result:   compatResult(report.Evidence.SemanticFloor),
		}
	}
	files := report.Evidence.ChangedFiles

	return attest.ReleaseInput{
		Tag:                    tagName,
		CommitSHA:              report.ToCommit,
		Component:              componentName,
		RangeFrom:              report.From,
		FromIsAdoptionBoundary: report.FromIsAdoptionBoundary,
		Effective:              comp.Effective,
		Own:                    comp.Own,
		FloorSource:            floorSource,
		DependenciesPinned:     pinned,
		Commits:                commits,
		Compat:                 compat,
		Blast: attest.ReleaseBlast{
			Files: &files,
			Score: blast,
			Inputs: map[string]any{
				"source":        "operator",
				"changed_files": files,
			},
		},
		Decision: attest.ReleaseDecision{
			ClaimedBump:   claimed.String(),
			SemanticFloor: report.Evidence.SemanticFloor,
			Strategy:      report.Policy.Strategy,
			Channel:       decision.Channel.String(),
			PolicyPath:    report.Policy.Path,
			PolicyDigest:  "sha256:" + report.Policy.Digest,
		},
		Timestamp: at,
	}, nil
}

// predicateReviewClass maps the classifier's review vocabulary (§3.2) onto
// the predicate's class enum: a distinct human reviewer is "human", an
// independent agent review is "agent", and everything else — including
// self-review — is "none" (the schema's documented collapse).
func predicateReviewClass(review string) string {
	switch review {
	case trust.ReviewHumanDistinct.String():
		return "human"
	case trust.ReviewAgentIndependent.String():
		return "agent"
	default:
		return "none"
	}
}

// compatResult renders the differ's verdict from the floor it produced
// (§6.1): an unchanged public surface permits PATCH, additive-only changes
// force MINOR, a breaking change forces MAJOR.
func compatResult(floor string) string {
	switch floor {
	case "patch":
		return "compatible"
	case "minor":
		return "additive"
	default:
		return "breaking"
	}
}

// parseRepositoryDigest parses the operator's --repository-digest into the
// digest set the §4.3 repository identity carries. It requires an explicit
// "<algo>:<hex>" so the algorithm is recorded, never guessed.
func parseRepositoryDigest(s string) (map[string]string, error) {
	algo, hexStr, ok := strings.Cut(s, ":")
	if !ok || algo == "" || hexStr == "" {
		return nil, fmt.Errorf("--repository-digest is required with --predicate v0.2 and must be <algo>:<hex> (e.g. sha256:...), got %q", s)
	}
	return map[string]string{algo: hexStr}, nil
}

// digestSetOf parses a "<algo>:<hex>" digest into the single-entry digest set the
// release/v0.2 wire shapes carry. A bare value (no "<algo>:") maps under sha256.
func digestSetOf(prefixed string) map[string]string {
	if algo, hexStr, ok := strings.Cut(prefixed, ":"); ok && algo != "" && hexStr != "" {
		return map[string]string{algo: hexStr}
	}
	return map[string]string{"sha256": prefixed}
}

// releaseDigestDesc maps a verify policy-state digest descriptor onto the attest
// release/v0.2 shape (same uri/path/digest fields, distinct packages).
func releaseDigestDesc(d verify.PolicyDigestDescriptor) attest.ReleaseDigestDescriptor {
	return attest.ReleaseDigestDescriptor{URI: d.URI, Path: d.Path, Digest: d.Digest}
}

func releaseDigestDescPtr(d *verify.PolicyDigestDescriptor) *attest.ReleaseDigestDescriptor {
	if d == nil {
		return nil
	}
	v := releaseDigestDesc(*d)
	return &v
}

func releaseDigestDescs(ds []verify.PolicyDigestDescriptor) []attest.ReleaseDigestDescriptor {
	out := make([]attest.ReleaseDigestDescriptor, 0, len(ds))
	for _, d := range ds {
		out = append(out, releaseDigestDesc(d))
	}
	return out
}

// releaseV02Input assembles the §8.1 release/v0.2 predicate from the M1–M5
// outputs: the authenticated policy state (B2's retained MetaPolicy), the ADR-036
// version state (whose resulting_state digest the CALLER computes here via
// version.StateDigest, keeping internal/attest uncoupled from the canonicalization),
// the verified provenance vector, the trust result, and the threshold-bearing
// decision. It builds everything EXCEPT version_state.emission.tag — the emitted
// tag's raw ref OID exists only after the tag is created, so the caller fills it
// after CreateSignedTag (dry-run leaves it null). Genesis only (M6 Phase B).
func releaseV02Input(report *verify.Report, comp verify.ComponentEffective, decision trust.Decision,
	vd versionDecision, desc *chain.BootstrapDescriptor, claimed evidence.Bump, blast string,
	repoDigest map[string]string, tagName string, at time.Time) (attest.ReleaseV02Input, error) {

	if report.PolicyState == nil {
		return attest.ReleaseV02Input{}, errors.New(
			"release refused: release/v0.2 needs the authenticated policy state (§5.4/ADR-028); none was produced (not a v0.10 run?)")
	}

	pred := report.Predecessor
	recurring := pred != nil

	// resulting_state.digest (ADR-036): genesis has no predecessor state (null
	// hash-chain link); a recurring release chains to the predecessor's
	// resulting_state.digest.
	var priorStateDigest *string
	if recurring {
		d := pred.ResultingStateDigest()
		priorStateDigest = &d
	}
	stateHex, err := version.StateDigest(
		version.CanonicalStateMap(desc.Component, desc.TagPrefix, vd.State, priorStateDigest))
	if err != nil {
		return attest.ReleaseV02Input{}, fmt.Errorf("release refused: version-state canonicalization failed: %w", err)
	}

	ps := report.PolicyState
	policyState := attest.ReleasePolicyState{
		ActivePolicy:        releaseDigestDesc(ps.ActivePolicy),
		ActiveTrustRoots:    releaseDigestDescs(ps.ActiveTrustRoots),
		CandidatePolicy:     releaseDigestDescPtr(ps.CandidatePolicy),
		CandidateTrustRoots: releaseDigestDescs(ps.CandidateTrustRoots),
		MandatoryWorkflows:  releaseDigestDescs(ps.MandatoryWorkflows),
		Authority:           ps.Authority,
		AuthorityIdentity:   releaseDigestDesc(ps.AuthorityIdentity),
	}

	provenance := make([]attest.ReleaseProvenanceCommit, 0, len(report.Commits))
	for _, c := range report.Commits {
		var reviewAtt *attest.ReleaseObjectRef
		if c.ReviewAttestation != "" {
			reviewAtt = &attest.ReleaseObjectRef{ID: "review-attestation:" + c.ReviewAttestation}
		}
		provenance = append(provenance, attest.ReleaseProvenanceCommit{
			SHA:   c.SHA,
			Level: c.Level,
			Authorship: attest.ReleaseAuthorship{
				Class:              c.Authorship,
				CredentialIdentity: c.Signer,
				Trailers:           c.Trailers,
			},
			Review: attest.ReleaseReviewRef{
				Class:       predicateReviewClass(c.Review),
				Actor:       c.ReviewIdentity,
				Attestation: reviewAtt,
			},
		})
	}

	// floor_sources is empty when the component floors itself (§5.3) — the
	// documented collapse the v0.1 floor_source=null convention also uses.
	var floorSources []attest.ReleaseObjectRef
	if comp.FloorSource != "" && comp.FloorSource != comp.Name {
		floorSources = []attest.ReleaseObjectRef{{ID: "component:" + comp.FloorSource}}
	}

	var compat *attest.ReleaseObjectRef
	if report.Evidence.DifferAvailable {
		compat = &attest.ReleaseObjectRef{ID: "compat:" + compatResult(report.Evidence.SemanticFloor)}
	}

	// interval: the adoption boundary rides in when the verify pipeline disclosed
	// one (ADR-026/ADR-028); inception carries none.
	var boundary *attest.ReleaseObjectRef
	if report.FromIsAdoptionBoundary && report.AdoptionBoundary != "" {
		boundary = &attest.ReleaseObjectRef{ID: "commit:" + report.AdoptionBoundary}
	}

	// Recurring emission facts: the interval mode, the cryptographic identity of
	// the predecessor attestation this release continues (§8.1/ADR-027), and the
	// prior_state (the predecessor's resulting state) — the ADR-036 hash-chain
	// link the successor's resulting_state.digest is computed against.
	intervalMode := desc.IntervalMode
	var predAttestation *attest.ReleaseObjectRef
	var priorState *attest.ReleaseStateIdentity
	if recurring {
		intervalMode = "recurring"
		predAttestation = &attest.ReleaseObjectRef{ID: pred.AttestationRef(), Digest: digestSetOf(pred.AttestationDigest())}
		priorState = &attest.ReleaseStateIdentity{
			ID:     "version-state:" + desc.Component + ":" + pred.Tag(),
			Digest: digestSetOf(pred.ResultingStateDigest()),
		}
	}

	// version_state.predecessor is the authenticated baseline binding (null new line).
	var predecessorTag *attest.ReleaseTagIdentity
	if vd.PredecessorTag != nil {
		predecessorTag = &attest.ReleaseTagIdentity{
			Name:            vd.PredecessorTag.Tag,
			RawRefOID:       vd.PredecessorTag.RefOID,
			PeeledCommitOID: vd.PredecessorTag.CommitOID,
		}
	}
	lineage := make([]attest.ReleaseObjectRef, 0, len(vd.State.TargetIntervals))
	for _, id := range vd.State.TargetIntervals {
		lineage = append(lineage, attest.ReleaseObjectRef{ID: id})
	}
	// version_state.iteration is present only for a prerelease cut (the trust-suffix
	// iteration); a clean cut carries null.
	var iteration *int
	if !vd.State.CleanAccepted {
		it := int(vd.Iteration)
		iteration = &it
	}

	return attest.ReleaseV02Input{
		TagName:   tagName,
		CommitSHA: report.ToCommit,
		Repository: attest.ReleaseV02Repository{
			ID:     desc.Repository,
			Digest: repoDigest,
		},
		Component: attest.ReleaseComponent{Name: desc.Component, TagPrefix: desc.TagPrefix},
		Interval: attest.ReleaseInterval{
			Mode:                   intervalMode,
			To:                     attest.ReleaseObjectRef{ID: "commit:" + report.ToCommit},
			AdoptionBoundary:       boundary,
			PredecessorAttestation: predAttestation,
			SourceIdentity:         map[string]string{"gitCommit": report.ToCommit},
		},
		PolicyState: policyState,
		VersionState: attest.ReleaseVersionState{
			Action:      vd.Action,
			Genesis:     !recurring,
			Predecessor: predecessorTag,
			PriorState:  priorState,
			ResultingState: attest.ReleaseStateIdentity{
				ID:     "version-state:" + desc.Component + ":" + tagName,
				Digest: map[string]string{"sha256": stateHex},
			},
			TargetCore:             vd.State.TargetCore,
			TargetBump:             vd.State.TargetBump,
			Emission:               attest.ReleaseTagEmission{Kind: "tag", Tag: nil}, // tag filled post-creation
			TargetLineage:          lineage,
			Iteration:              iteration,
			PendingCorrectiveFloor: vd.State.CorrectiveFloor,
		},
		Trust: attest.ReleaseTrust{
			Effective:    comp.Effective,
			Own:          comp.Own,
			FloorSources: floorSources,
		},
		Provenance: provenance,
		Evidence: attest.ReleaseEvidence{
			Compatibility: compat,
			BlastRadius:   attest.ReleaseObjectRef{ID: "blast:" + blast},
			Coverage:      nil,
		},
		Decision: attest.ReleaseV02Decision{
			ClaimedBump:   claimed.String(),
			SemanticFloor: report.Evidence.SemanticFloor,
			Threshold:     report.Policy.Threshold,
			Strategy:      report.Policy.Strategy,
			Channel:       decision.Channel.String(),
			Supersedes:    nil,
		},
		Timestamp: at,
	}, nil
}

// loadSignerFile loads an OpenSSH private key from a flag-named path.
func loadSignerFile(path, flag string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flag, err)
	}
	signer, err := sshsig.LoadSigner(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flag, err)
	}
	return signer, nil
}

// releaseResult is the release command's output shape, JSON and human.
type releaseResult struct {
	DryRun        bool   `json:"dry_run,omitempty"`
	Channel       string `json:"channel"`
	Version       string `json:"version"`
	Tag           string `json:"tag"`
	ToCommit      string `json:"to_commit"`
	Bump          string `json:"bump"`
	ClaimedBump   string `json:"claimed_bump"`
	SemanticFloor string `json:"semantic_floor"`
	Effective     string `json:"effective"`
	Own           string `json:"own"`
	Blast         string `json:"blast"`
	Strategy      string `json:"strategy"`
	Iteration     uint64 `json:"iteration"`
	// VersionAuthenticated is true when a bootstrap descriptor governed the
	// version line (v0.10 mode); VersionPredecessor is the authenticated
	// predecessor tag it continues from, nil for a descriptor-declared new line.
	VersionAuthenticated bool           `json:"version_authenticated,omitempty"`
	VersionPredecessor   *string        `json:"version_predecessor,omitempty"`
	PredicateType        string         `json:"predicate_type"`
	Signer               string         `json:"attestation_signer,omitempty"`
	StoredRefs           []string       `json:"stored_refs,omitempty"`
	Report               *verify.Report `json:"report"`
}

// render writes the result: structured JSON under --json, the human summary
// otherwise. payload is the would-be statement a --dry-run prints.
func (r releaseResult) render(cmd *cobra.Command, jsonOut bool, payload []byte) error {
	if jsonOut {
		out := struct {
			releaseResult
			Statement json.RawMessage `json:"statement,omitempty"`
		}{releaseResult: r, Statement: payload}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	w := &errWriter{w: cmd.OutOrStdout()}
	w.printf("release decision (spec §10 step 8)\n")
	w.printf("  channel:        %s\n", r.Channel)
	w.printf("  version:        %s\n", r.Version)
	if r.VersionAuthenticated {
		if r.VersionPredecessor != nil {
			w.printf("  version line:   continues %s (authenticated, §7.5/ADR-029)\n", *r.VersionPredecessor)
		} else {
			w.printf("  version line:   new line (authenticated null predecessor, §7.5/ADR-029)\n")
		}
	}
	w.printf("  bump:           %s (claimed %s, semantic floor %s)\n", r.Bump, r.ClaimedBump, r.SemanticFloor)
	w.printf("  effective:      %s (own %s)\n", r.Effective, r.Own)
	w.printf("  blast:          %s (operator-supplied)\n", r.Blast)
	w.printf("  strategy:       %s\n", r.Strategy)
	if r.DryRun {
		w.printf("dry-run: no tag created, nothing stored\n")
		w.printf("  would-be tag:  %s -> %s\n", r.Tag, r.ToCommit)
		w.printf("  would-be attestation (%s):\n", r.PredicateType)
		if len(payload) > 0 {
			var pretty json.RawMessage = payload
			indented, err := json.MarshalIndent(pretty, "    ", "  ")
			if err != nil {
				return err
			}
			w.printf("    %s\n", indented)
		}
		return w.err
	}
	w.printf("tag %s -> %s (signed annotated, SSHSIG namespace \"git\")\n", r.Tag, r.ToCommit)
	w.printf("release attestation %s\n", r.PredicateType)
	w.printf("  signer: %s\n", r.Signer)
	for i, ref := range r.StoredRefs {
		if i == 0 {
			w.printf("  stored: %s\n", ref)
		} else {
			w.printf("          %s\n", ref)
		}
	}
	return w.err
}
