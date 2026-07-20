// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/evidence"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/chain"
	"github.com/semver-trust/semver-trust-go/internal/trust"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
	"github.com/semver-trust/semver-trust-go/internal/verify"
	"github.com/semver-trust/semver-trust-go/internal/version"
)

// newPromoteCmd is the `promote` subcommand: spec §7.3 / ADR-009 promotion.
// Promotion moves a release from the pre-release channel to the clean channel
// WITHOUT changing its source (§7.3): the same commit SHA is re-evaluated with
// the evidence that has since accumulated, and — if it now qualifies — the
// clean tag lands on the identical commit, carrying a fresh release
// attestation that supersedes the prior one (§10 step 10).
//
// promote reuses the entire release pipeline. It differs from release only at
// the edges: the operator does not restate the change (no --claimed-bump /
// --iteration) — those describe the same change set and are carried over from
// the prior attestation; only the evidence moved. What changes the outcome is
// the current attestation store, re-read at the same SHA.
func newPromoteCmd() *cobra.Command {
	var (
		// The verify surface, unchanged (steps 1–7 are the same pipeline as
		// release, run at the pre-release tag's own commit).
		repoPath           string
		policyPath         string
		allowedSigners     string
		attestationSigners string
		gpgKeyring         string
		component          string
		verifyTime         string
		jsonOut            bool

		// The promotion surface.
		tag         string // the existing pre-release trust tag being promoted
		blast       string // §6.2 score override; empty carries the prior attestation's
		tagKeyPath  string
		attKeyPath  string
		taggerName  string
		taggerEmail string
		dryRun      bool

		// The v0.10 supersede surface (§8.1/ADR-030; opt-in, requires a descriptor).
		bootstrapDescriptor string
		repositoryDigest    string
	)

	cmd := &cobra.Command{
		Use:   "promote",
		Short: "Promote a pre-release to the clean channel on the identical SHA (spec §7.3, ADR-009)",
		Long: `promote re-runs the §10 decision at an existing pre-release tag's own commit
with the evidence that has accumulated since it was cut, and — if the release
now qualifies for the clean channel — creates the clean tag on the IDENTICAL
SHA and publishes a superseding release attestation (§7.3, §10 step 10).

The source never changes. --tag names an existing pre-release trust version
(e.g. v1.4.0-t0.3); promote resolves it to its commit, loads the policy from
that tree, and locates the prior release attestation stored under the tag. The
claimed bump and blast score are NOT restated — they describe the same change
set and are carried from the prior attestation; only the evidence, re-read from
the current attestation store, moves. (--blast may override the carried score
when a fresh blast assessment is warranted.)

Promotion is not re-cutting. If the re-evaluation still lands in the
pre-release channel, promote refuses outright — cutting a new pre-release
iteration is release's job (§7.2), not promotion's. If it qualifies clean, the
clean tag is created on the same SHA (refused if it already exists) and the new
attestation's supersedes points at the prior envelope's stable ref (§8.1),
storing under both the new tag and the commit. --dry-run evaluates, decides,
and prints the would-be promotion without writing anything.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The clock is read once, here at the process boundary, and
			// injected everywhere (ADR-018).
			at := time.Now()
			if verifyTime != "" {
				parsed, err := time.Parse(time.RFC3339, verifyTime)
				if err != nil {
					return err
				}
				at = parsed
			}

			// --tag must parse as a §7.1 trust version AND be a pre-release:
			// promotion has nothing to promote from a clean tag.
			preVer, err := version.Parse(tag)
			if err != nil {
				return fmt.Errorf("--tag must be a §7.1 trust version: %w", err)
			}
			if preVer.Trust == nil {
				return fmt.Errorf("promote refused: --tag %s is already a clean release; promotion moves a pre-release to the clean channel (§7.3)", tag)
			}
			// The clean tag is the same core with the trust suffix dropped
			// (§7.3: v1.4.0 from v1.4.0-t0.3).
			cleanVer := version.Version{Component: preVer.Component, Major: preVer.Major, Minor: preVer.Minor, Patch: preVer.Patch}

			// Signing material resolves before any evaluation so a missing key
			// fails fast. --dry-run writes nothing and needs no keys.
			var tagSigner, attSigner ssh.Signer
			if !dryRun {
				if tagKeyPath == "" || attKeyPath == "" {
					return errors.New("promote signs a tag and an attestation: --tag-key and --attest-key are required (or use --dry-run)")
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

			// ---- §7.3 step 1: resolve the pre-release tag to its commit and
			// locate the prior release attestation. ------------------------
			toCommit, err := vcs.ResolveCommit(repoPath, tag)
			if err != nil {
				return fmt.Errorf("promote refused: --tag %s does not resolve to a commit: %w", tag, err)
			}

			// ---- v0.10 supersede path (§7.3/§7.5/ADR-030): when a bootstrap
			// descriptor is supplied, the promotion re-evaluates the AUTHENTICATED
			// accepted chain head at its own commit under the §7.5 superseded
			// authority and emits a release/v0.2 that supersedes the prior
			// attestation and advances the chain to the clean tag. The v0.1 path
			// below stays byte-for-byte when no descriptor is supplied. --------
			if bootstrapDescriptor != "" {
				return promoteSupersede(cmd, promoteSupersedeInputs{
					repoPath: repoPath, policyPath: policyPath, component: component,
					descriptorPath: bootstrapDescriptor, repositoryDigest: repositoryDigest,
					allowedSigners: allowedSigners, gpgKeyring: gpgKeyring, attestationSigners: attestationSigners,
					tag: tag, cleanVer: cleanVer, toCommit: toCommit, blastOverride: blast,
					dryRun: dryRun, jsonOut: jsonOut, tagSigner: tagSigner, attSigner: attSigner,
					taggerName: taggerName, taggerEmail: taggerEmail, at: at,
				})
			}

			prior, err := priorRelease(repoPath, tag)
			if err != nil {
				return err
			}

			// The claimed bump and blast carry from the prior attestation:
			// they describe the same change set, only the evidence moved. An
			// explicit --blast overrides the carried score.
			claimed, err := evidence.ParseBump(prior.claimedBump)
			if err != nil {
				return fmt.Errorf("prior attestation's claimed bump is unusable: %w", err)
			}
			carriedBlast := prior.blast
			if blast != "" {
				carriedBlast = blast
			}
			blastScore, err := trust.ParseBlast(carriedBlast)
			if err != nil {
				return fmt.Errorf("--blast: %w", err)
			}

			// The range reproduces the prior release's: an adoption-boundary
			// first release re-derives the boundary from policy (From empty),
			// otherwise the prior range.from (empty for a plain first release).
			fromArg := prior.rangeFrom
			if prior.fromIsBoundary {
				fromArg = ""
			}

			// ---- §7.3 step 2: re-run §10 steps 1-7 at the SAME commit with
			// the current attestation store — the new evidence. -------------
			report, err := verify.Verify(verify.Options{
				RepoPath:               repoPath,
				From:                   fromArg,
				To:                     toCommit,
				PolicyPath:             policyPath,
				AllowedSignersPath:     allowedSigners,
				AttestationSignersPath: attestationSigners,
				GPGKeyringPath:         gpgKeyring,
				Component:              component,
				VerifyTime:             at,
			})
			if err != nil {
				return fmt.Errorf("promote refused: %w", err)
			}

			// The claimed bump / semantic floor / blast are carried over from
			// the prior decision block; trust.Decide runs against the freshly
			// computed effective trust.
			decision, comp, err := decideRelease(report, fromArg, component, claimed, blastScore, preVer.Trust.Iteration)
			if err != nil {
				return err
			}

			// ---- §7.3 step 3: still pre-release ⇒ refuse. Promotion is not
			// re-cutting: a run that does not reach the clean channel has not
			// been promoted, whatever level it now computes. ----------------
			if decision.Channel != trust.ChannelClean {
				return fmt.Errorf("promote refused: evidence has not changed the decision — %s still lands in the pre-release channel (effective %s, blast %s); promotion moves a release to the clean channel, it does not re-cut a new pre-release iteration (§7.3, §7.2)",
					tag, comp.Effective, carriedBlast)
			}

			// The clean tag the decision produces must be the pre-release
			// tag's core with the suffix dropped: if it is not, the tag and
			// its attestation's recorded range/claim disagree.
			if decision.Version.String() != cleanVer.String() {
				return fmt.Errorf("promote refused: the decision would produce %s but the pre-release tag's core is %s (the tag and its attestation's recorded range/claim disagree)",
					decision.Version, cleanVer)
			}
			tagName := cleanVer.String()

			// ---- §7.3 step 4: the clean tag lands on the identical SHA;
			// refuse to move it if it exists (a promotion never overwrites). -
			if exists, err := vcs.TagExists(repoPath, tagName); err != nil {
				return err
			} else if exists {
				return fmt.Errorf("promote refused: %w: %s is already published (a clean tag is created once, on the identical SHA, §7.3)",
					vcs.ErrTagExists, tagName)
			}

			input, err := releaseStatementInput(report, comp, decision, claimed, carriedBlast, tagName, component, at)
			if err != nil {
				return err
			}
			// supersedes points at the prior envelope's stable ref (§8.1),
			// named by the shared commit subject — the promotion chain.
			input.Decision.Supersedes = attest.EnvelopeRef(toCommit, prior.envelope)

			result := promoteResult{
				DryRun:        dryRun,
				Tag:           tagName,
				PromotedFrom:  tag,
				Channel:       decision.Channel.String(),
				Version:       decision.Version.String(),
				ToCommit:      report.ToCommit,
				Bump:          decision.Bump.String(),
				ClaimedBump:   claimed.String(),
				SemanticFloor: report.Evidence.SemanticFloor,
				Effective:     comp.Effective,
				Own:           comp.Own,
				Blast:         carriedBlast,
				Strategy:      report.Policy.Strategy,
				Supersedes:    input.Decision.Supersedes,
				PredicateType: attest.PredicateRelease,
				Report:        report,
			}

			if dryRun {
				payload, err := attest.BuildReleaseStatement(input)
				if err != nil {
					return err
				}
				return result.render(cmd, jsonOut, payload)
			}

			// ---- §7.3 step 4 (emit): validate, sign, and self-verify the
			// superseding attestation BEFORE the tag ref moves. -------------
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

			message := fmt.Sprintf("%s\n\nSemVer-Trust promotion of %s: channel clean, effective trust %s (§7.3, same SHA).\n",
				tagName, tag, comp.Effective)
			if err := vcs.CreateSignedTag(repoPath, tagName, report.ToCommit, taggerName, taggerEmail, message, at, tagSigner); err != nil {
				return err
			}

			// Stored under BOTH subjects (§8.2): a verifier looking the
			// promotion up by commit or by the new tag finds the same envelope.
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
	f.StringVar(&tag, "tag", "", "existing pre-release trust tag to promote (required; must parse as a §7.1 trust version)")
	f.StringVar(&repoPath, "repo", ".", "repository to promote in")
	f.StringVar(&policyPath, "policy", ".semver-trust/policy.toml", "policy file path within the tag's tree")
	f.StringVar(&allowedSigners, "allowed-signers", "", "filesystem allowed-signers override; empty resolves the policy's identity.human.allowed_signers from the tag's tree")
	f.StringVar(&attestationSigners, "attestation-signers", "", "filesystem attestation-signer registry; overrides the policy. Empty resolves [identity] attestation_signers from the tag's tree (§9); if the policy declares none either, reviews cannot be verified and classify none")
	f.StringVar(&gpgKeyring, "gpg-keyring", "", "armored OpenPGP public keyring for GPG-signed commits; overrides the policy. Empty resolves [identity.human] gpg_keyring from the tag's tree (§9); if the policy declares none either, the GPG key family is unverifiable and fails closed")
	f.StringVar(&component, "component", "", "component to promote (tag prefix and attestation component); empty = the single/root component")
	f.StringVar(&verifyTime, "verify-time", "", "verification instant (RFC3339); empty = now at the CLI boundary")
	f.BoolVar(&jsonOut, "json", false, "emit a structured JSON result instead of the human summary")
	f.StringVar(&blast, "blast", "", "override the §6.2 blast-radius score (low|moderate|high); empty carries the prior attestation's score")
	f.StringVar(&tagKeyPath, "tag-key", "", "OpenSSH private key signing the clean tag (git namespace)")
	f.StringVar(&attKeyPath, "attest-key", "", "OpenSSH private key signing the release attestation (attestation namespace; may equal --tag-key)")
	f.StringVar(&taggerName, "tagger-name", "", "tagger name; empty resolves git config user.name")
	f.StringVar(&taggerEmail, "tagger-email", "", "tagger email; empty resolves git config user.email")
	f.BoolVar(&dryRun, "dry-run", false, "evaluate and decide, print the would-be promotion, write nothing")
	f.StringVar(&bootstrapDescriptor, "bootstrap-descriptor", "", "out-of-band v0.10 bootstrap descriptor (§5.4/§7.5, ADR-028/029); when supplied, promotion re-evaluates the accepted chain head under the authenticated §7.5 supersede authority and emits a release/v0.2. Must be supplied from outside the repository")
	f.StringVar(&repositoryDigest, "repository-digest", "", "canonical repository identity digest (<algo>:<hex>, §4.3) bound into a release/v0.2 supersede; required with --bootstrap-descriptor")
	if err := cmd.MarkFlagRequired("tag"); err != nil {
		panic(err)
	}
	return cmd
}

// promoteSupersedeInputs carries the v0.10 supersede path's parameters out of the
// RunE closure (§7.3/§7.5/ADR-030).
type promoteSupersedeInputs struct {
	repoPath           string
	policyPath         string
	component          string
	descriptorPath     string
	repositoryDigest   string
	allowedSigners     string
	gpgKeyring         string
	attestationSigners string
	tag                string
	cleanVer           version.Version
	toCommit           string
	blastOverride      string
	dryRun             bool
	jsonOut            bool
	tagSigner          ssh.Signer
	attSigner          ssh.Signer
	taggerName         string
	taggerEmail        string
	at                 time.Time
}

// promoteSupersede runs the v0.10 promotion (§7.3/§7.5/ADR-030): it authenticates
// the accepted chain, re-evaluates the superseded release at its OWN commit under
// the §7.5 superseded authority (verify.Options.Supersede — a plain recurring verify
// would discover the head and abort promotion_required, its interval being P..P),
// and emits a release/v0.2 that supersedes the prior attestation and advances the
// chain to the clean tag (§8.1/ADR-036). The claimed bump and blast carry from the
// superseded attestation; only the accumulated evidence moves.
func promoteSupersede(cmd *cobra.Command, in promoteSupersedeInputs) error {
	desc, err := chain.LoadBootstrapDescriptor(in.descriptorPath, in.repoPath)
	if err != nil {
		return fmt.Errorf("promote refused: %w", err)
	}
	repoDigest, err := parseRepositoryDigest(in.repositoryDigest)
	if err != nil {
		return fmt.Errorf("promote refused: %w", err)
	}

	// The attestation verifier is built from the policy in the superseded commit's
	// tree; it fresh-verifies every stored release/v0.2 so the chain head is trusted,
	// never claimed (§7.5/ADR-027). Bootstrap is set so AttestationVerifier enforces
	// the v0.10 fail-closed rule: a filesystem trust-material override (passed through
	// below) is rejected rather than silently honored when building the chain verifier
	// — the chain head MUST be verified against descriptor-pinned material (§5.4/ADR-028).
	av, err := verify.AttestationVerifier(verify.Options{
		RepoPath:               in.repoPath,
		To:                     in.toCommit,
		PolicyPath:             in.policyPath,
		Component:              in.component,
		VerifyTime:             in.at,
		Bootstrap:              desc,
		AllowedSignersPath:     in.allowedSigners,
		GPGKeyringPath:         in.gpgKeyring,
		AttestationSignersPath: in.attestationSigners,
	})
	if err != nil {
		return fmt.Errorf("promote refused: %w", err)
	}
	if av == nil {
		return errors.New("promote refused: the policy declares no attestation signers, so the accepted chain cannot be verified — a v0.10 supersede needs [identity] attestation_signers (§9)")
	}

	superseded, anchor, err := chain.SupersedeHead(in.repoPath, desc.Repository, desc.Component, av, in.at)
	if err != nil {
		return fmt.Errorf("promote refused: %w", err)
	}
	if superseded == nil {
		return fmt.Errorf("promote refused: no accepted release/v0.2 chain head for component %q — there is nothing to supersede (§7.5/ADR-029)", desc.Component)
	}
	// The chain head the reader selected MUST be the tag the operator is promoting:
	// a promotion supersedes a specific release, not "whatever the head happens to be".
	if superseded.Tag() != in.tag {
		return fmt.Errorf("promote refused: --tag %s is not the accepted chain head (%s @ %s) — a promotion supersedes the accepted head (§7.3/§7.5)", in.tag, superseded.Tag(), shortSHA(superseded.To()))
	}
	if superseded.To() != in.toCommit {
		return fmt.Errorf("promote refused: chain head %s resolves to %s, not --tag %s's commit %s", superseded.Tag(), shortSHA(superseded.To()), in.tag, shortSHA(in.toCommit))
	}

	// The claimed bump and blast carry from the superseded release/v0.2 (§7.3: the
	// same source, only the evidence moved); --blast overrides the carried score.
	claimed, err := evidence.ParseBump(superseded.ClaimedBump())
	if err != nil {
		return fmt.Errorf("promote refused: the superseded attestation's claimed bump is unusable: %w", err)
	}
	carriedBlast := superseded.Blast()
	if in.blastOverride != "" {
		carriedBlast = in.blastOverride
	}
	blastScore, err := trust.ParseBlast(carriedBlast)
	if err != nil {
		return fmt.Errorf("--blast: %w", err)
	}

	// ---- §7.3 step 2: re-run §10 steps 1–7 at the SAME commit in supersede mode.
	// Supersede re-runs the superseded's OWN interval via the caller-supplied anchor
	// (its predecessor; nil → the descriptor's genesis interval). --------------
	report, err := verify.Verify(verify.Options{
		RepoPath:               in.repoPath,
		To:                     in.toCommit,
		PolicyPath:             in.policyPath,
		Component:              in.component,
		VerifyTime:             in.at,
		Bootstrap:              desc,
		Supersede:              true,
		Predecessor:            anchor,
		AllowedSignersPath:     in.allowedSigners,
		GPGKeyringPath:         in.gpgKeyring,
		AttestationSignersPath: in.attestationSigners,
	})
	if err != nil {
		return fmt.Errorf("promote refused: %w", err)
	}

	// ---- §7.3 step 3: decide the supersede under the §7.5 superseded authority.
	vd, err := decidePromote(report, desc, in.repoPath, claimed, blastScore, superseded)
	if err != nil {
		return err
	}
	// Promotion is not re-cutting: a re-evaluation that does not reach the clean
	// channel has not been promoted (§7.3, §7.2).
	if vd.Decision.Channel != trust.ChannelClean {
		return fmt.Errorf("promote refused: evidence has not changed the decision — %s still lands in the pre-release channel (effective %s, blast %s); promotion moves a release to the clean channel, it does not re-cut a new pre-release iteration (§7.3, §7.2)",
			in.tag, vd.Component.Effective, carriedBlast)
	}
	if vd.Decision.Version.String() != in.cleanVer.String() {
		return fmt.Errorf("promote refused: the decision would produce %s but the pre-release tag's core is %s (the tag and its attestation's recorded state disagree)",
			vd.Decision.Version, in.cleanVer)
	}
	tagName := in.cleanVer.String()

	// ---- §7.3 step 4: the clean tag lands on the identical SHA; never move it. -
	if exists, err := vcs.TagExists(in.repoPath, tagName); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("promote refused: %w: %s is already published (a clean tag is created once, on the identical SHA, §7.3)",
			vcs.ErrTagExists, tagName)
	}

	v02, err := releaseV02Input(report, vd.Component, vd.Decision, vd, desc, superseded, claimed, carriedBlast, repoDigest, tagName, in.at)
	if err != nil {
		return err
	}

	result := promoteResult{
		DryRun:        in.dryRun,
		Tag:           tagName,
		PromotedFrom:  in.tag,
		Channel:       vd.Decision.Channel.String(),
		Version:       vd.Decision.Version.String(),
		ToCommit:      report.ToCommit,
		Bump:          vd.Decision.Bump.String(),
		ClaimedBump:   claimed.String(),
		SemanticFloor: report.Evidence.SemanticFloor,
		Effective:     vd.Component.Effective,
		Own:           vd.Component.Own,
		Blast:         carriedBlast,
		Strategy:      report.Policy.Strategy,
		Supersedes:    superseded.AttestationRef(),
		PredicateType: attest.PredicateReleaseV02,
		Report:        report,
	}

	if in.dryRun {
		// Preview: no tag is created, so emission.tag stays null.
		payload, err := attest.BuildReleaseV02Statement(v02)
		if err != nil {
			return err
		}
		return result.render(cmd, in.jsonOut, payload)
	}

	// ---- §7.3 step 4 (emit): the release/v0.2 arm REORDERS — emission.tag binds
	// the signed tag object's raw ref OID, which exists only after the tag is
	// created, and signed bytes are frozen. ADR-036 excludes emission from the
	// resulting_state.digest, so the state hash is already stable; only the emission
	// block needs the OID. An Emit/store failure best-effort deletes the tag (an
	// orphan tag carries no release attestation, and verify never trusts one). -----
	releaseSchema, err := conformance.Vector("schemas/release-v0.2.json")
	if err != nil {
		return err
	}
	emitter, err := attest.NewReleaseV02Emitter(in.attSigner, releaseSchema)
	if err != nil {
		return err
	}
	message := fmt.Sprintf("%s\n\nSemVer-Trust promotion of %s: channel clean, effective trust %s (§7.3, same SHA).\n",
		tagName, in.tag, vd.Component.Effective)
	if err := vcs.CreateSignedTag(in.repoPath, tagName, report.ToCommit, in.taggerName, in.taggerEmail, message, in.at, in.tagSigner); err != nil {
		return err
	}
	peeled, err := vcs.TagRefs(in.repoPath)
	if err != nil {
		_ = vcs.DeleteTag(in.repoPath, tagName)
		return err
	}
	ref, ok := peeled[tagName]
	if !ok {
		_ = vcs.DeleteTag(in.repoPath, tagName)
		return fmt.Errorf("promote refused: created tag %q is absent from the ref-set; cannot bind version_state.emission", tagName)
	}
	v02.VersionState.Emission.Tag = &attest.ReleaseTagIdentity{
		Name:            tagName,
		RawRefOID:       ref.RefOID,
		PeeledCommitOID: ref.CommitOID,
	}
	emission, err := emitter.Emit(v02)
	if err != nil {
		_ = vcs.DeleteTag(in.repoPath, tagName)
		return err
	}
	// A partial or failed store must roll the tag back too (the reorder created it
	// before the store): a tag with no complete release attestation is the orphan
	// state the reorder exists to prevent. Already-written attestation refs are inert
	// without the tag — surfaced for the operator to prune, not deleted.
	refs, err := attest.StoreForSubjects(
		attest.GitRefStore{Path: in.repoPath}, []string{report.ToCommit, tagName}, emission.Envelope)
	if err != nil {
		_ = vcs.DeleteTag(in.repoPath, tagName)
		if len(refs) > 0 {
			return fmt.Errorf("promote refused: storing the release/v0.2 attestation failed after %d of 2 subjects; the tag was rolled back, prune the partial attestation refs %v: %w",
				len(refs), refs, err)
		}
		return fmt.Errorf("promote refused: storing the release/v0.2 attestation failed; the tag was rolled back: %w", err)
	}
	result.Signer = emission.KeyID
	result.StoredRefs = refs
	return result.render(cmd, in.jsonOut, nil)
}

// shortSHA abbreviates a commit SHA for diagnostics, tolerating short inputs.
func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// priorReleaseInfo is what a promotion carries over from the release it
// supersedes: the envelope itself (for the supersedes ref) plus the change-set
// facts promote does not restate (§7.3).
type priorReleaseInfo struct {
	envelope       []byte
	claimedBump    string
	blast          string
	rangeFrom      string
	fromIsBoundary bool
}

// priorRelease locates the release attestation stored under a pre-release tag
// name (§8.2, GitRefStore.List) and extracts the facts a promotion carries
// over. Exactly one release attestation must exist under the tag: none means
// there is nothing to supersede; more than one means an ambiguous store the
// operator must resolve.
func priorRelease(repoPath, tag string) (priorReleaseInfo, error) {
	envelopes, err := attest.GitRefStore{Path: repoPath}.List(tag)
	if err != nil {
		return priorReleaseInfo{}, err
	}

	var (
		found   priorReleaseInfo
		matched int
	)
	for _, env := range envelopes {
		payload, err := decodeEnvelopePayload(env)
		if err != nil {
			return priorReleaseInfo{}, err
		}
		var stmt priorReleasePayload
		if err := json.Unmarshal(payload, &stmt); err != nil {
			return priorReleaseInfo{}, err
		}
		if stmt.PredicateType != attest.PredicateRelease {
			continue
		}
		matched++
		rangeFrom := ""
		if stmt.Predicate.Range.From != nil {
			rangeFrom = *stmt.Predicate.Range.From
		}
		found = priorReleaseInfo{
			envelope:       env,
			claimedBump:    stmt.Predicate.Decision.ClaimedBump,
			blast:          stmt.Predicate.Evidence.BlastRadius.Score,
			rangeFrom:      rangeFrom,
			fromIsBoundary: stmt.Predicate.Range.FromIsAdoptionBoundary,
		}
	}
	switch matched {
	case 0:
		return priorReleaseInfo{}, fmt.Errorf("promote refused: no release attestation is stored under %s — nothing to supersede (§7.3)", tag)
	case 1:
		return found, nil
	default:
		return priorReleaseInfo{}, fmt.Errorf("promote refused: %d release attestations are stored under %s; the store is ambiguous", matched, tag)
	}
}

// decodeEnvelopePayload extracts the in-toto Statement bytes from a DSSE
// envelope (the base64 payload) without verifying it: the prior attestation is
// read only for the carry-over facts, and the fresh verify re-establishes
// trust from scratch at the same SHA.
func decodeEnvelopePayload(envelope []byte) ([]byte, error) {
	var env attest.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(env.Payload)
}

// priorReleasePayload is the subset of the §8.1 release payload a promotion
// reads from the prior attestation.
type priorReleasePayload struct {
	PredicateType string `json:"predicateType"`
	Predicate     struct {
		Range struct {
			From                   *string `json:"from"`
			FromIsAdoptionBoundary bool    `json:"from_is_adoption_boundary"`
		} `json:"range"`
		Evidence struct {
			BlastRadius struct {
				Score string `json:"score"`
			} `json:"blast_radius"`
		} `json:"evidence"`
		Decision struct {
			ClaimedBump string `json:"claimed_bump"`
		} `json:"decision"`
	} `json:"predicate"`
}

// promoteResult is the promote command's output shape, JSON and human. It
// mirrors releaseResult with the promotion-specific fields (the pre-release
// tag it superseded and the supersedes ref).
type promoteResult struct {
	DryRun        bool           `json:"dry_run,omitempty"`
	Tag           string         `json:"tag"`
	PromotedFrom  string         `json:"promoted_from"`
	Channel       string         `json:"channel"`
	Version       string         `json:"version"`
	ToCommit      string         `json:"to_commit"`
	Bump          string         `json:"bump"`
	ClaimedBump   string         `json:"claimed_bump"`
	SemanticFloor string         `json:"semantic_floor"`
	Effective     string         `json:"effective"`
	Own           string         `json:"own"`
	Blast         string         `json:"blast"`
	Strategy      string         `json:"strategy"`
	Supersedes    string         `json:"supersedes"`
	PredicateType string         `json:"predicate_type"`
	Signer        string         `json:"attestation_signer,omitempty"`
	StoredRefs    []string       `json:"stored_refs,omitempty"`
	Report        *verify.Report `json:"report"`
}

// render writes the promotion result: structured JSON under --json, the human
// summary otherwise. payload is the would-be statement a --dry-run prints.
func (r promoteResult) render(cmd *cobra.Command, jsonOut bool, payload []byte) error {
	if jsonOut {
		out := struct {
			promoteResult
			Statement json.RawMessage `json:"statement,omitempty"`
		}{promoteResult: r, Statement: payload}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	w := &errWriter{w: cmd.OutOrStdout()}
	w.printf("promotion decision (spec §7.3, same SHA)\n")
	w.printf("  promoted from:  %s\n", r.PromotedFrom)
	w.printf("  clean tag:      %s -> %s\n", r.Tag, r.ToCommit)
	w.printf("  channel:        %s\n", r.Channel)
	w.printf("  bump:           %s (claimed %s, semantic floor %s)\n", r.Bump, r.ClaimedBump, r.SemanticFloor)
	w.printf("  effective:      %s (own %s)\n", r.Effective, r.Own)
	w.printf("  blast:          %s\n", r.Blast)
	w.printf("  supersedes:     %s\n", r.Supersedes)
	if r.DryRun {
		w.printf("dry-run: no tag created, nothing stored\n")
		w.printf("  would-be attestation (%s):\n", r.PredicateType)
		if len(payload) > 0 {
			indented, err := json.MarshalIndent(json.RawMessage(payload), "    ", "  ")
			if err != nil {
				return err
			}
			w.printf("    %s\n", indented)
		}
		return w.err
	}
	w.printf("tag %s -> %s (signed annotated, SSHSIG namespace \"git\")\n", r.Tag, r.ToCommit)
	w.printf("release attestation %s (supersedes the prior decision, §8.1)\n", r.PredicateType)
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
