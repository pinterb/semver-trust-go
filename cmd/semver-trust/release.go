// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/evidence"
	"github.com/semver-trust/semver-trust-go/internal/attest"
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
		repoPath           string
		from               string
		to                 string
		policyPath         string
		allowedSigners     string
		attestationSigners string
		gpgKeyring         string
		component          string
		verifyTime         string
		jsonOut            bool

		// The release surface (steps 8–9).
		claimedBump string
		blast       string
		iteration   uint64
		tagKeyPath  string
		attKeyPath  string
		taggerName  string
		taggerEmail string
		dryRun      bool
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
			})
			if err != nil {
				return fmt.Errorf("release refused: %w", err)
			}

			// ---- §10 step 8: decide channel and version. -------------------
			decision, comp, err := decideRelease(report, from, component, claimed, blastScore, iteration)
			if err != nil {
				return err
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

			input, err := releaseStatementInput(report, comp, decision, claimed, blast, tagName, component, at)
			if err != nil {
				return err
			}

			result := releaseResult{
				DryRun:        dryRun,
				Channel:       decision.Channel.String(),
				Version:       decision.Version.String(),
				Tag:           tagName,
				ToCommit:      report.ToCommit,
				Bump:          decision.Bump.String(),
				ClaimedBump:   claimed.String(),
				SemanticFloor: report.Evidence.SemanticFloor,
				Effective:     comp.Effective,
				Own:           comp.Own,
				Blast:         blast,
				Strategy:      report.Policy.Strategy,
				Iteration:     iteration,
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

			// ---- §10 step 9: emit. The envelope is built, schema-validated,
			// signed, and self-verified BEFORE the tag ref moves, so the only
			// failure mode that can leave a tag without its attestation is a
			// storage write error.
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
	f.BoolVar(&jsonOut, "json", false, "emit a structured JSON result instead of the human summary")
	f.StringVar(&claimedBump, "claimed-bump", "", "the bump this release claims: patch|minor|major (required)")
	f.StringVar(&blast, "blast", "", "operator-supplied §6.2 blast-radius score: low|moderate|high (required; recorded as operator-supplied in the attestation)")
	f.Uint64Var(&iteration, "iteration", 1, "trust-suffix iteration for a pre-release cut (§7.2 re-cuts increment it)")
	f.StringVar(&tagKeyPath, "tag-key", "", "OpenSSH private key signing the tag (git namespace)")
	f.StringVar(&attKeyPath, "attest-key", "", "OpenSSH private key signing the release attestation (attestation namespace; may equal --tag-key)")
	f.StringVar(&taggerName, "tagger-name", "", "tagger name; empty resolves git config user.name")
	f.StringVar(&taggerEmail, "tagger-email", "", "tagger email; empty resolves git config user.email")
	f.BoolVar(&dryRun, "dry-run", false, "evaluate and decide, print the would-be tag and attestation, write nothing")
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
	DryRun        bool           `json:"dry_run,omitempty"`
	Channel       string         `json:"channel"`
	Version       string         `json:"version"`
	Tag           string         `json:"tag"`
	ToCommit      string         `json:"to_commit"`
	Bump          string         `json:"bump"`
	ClaimedBump   string         `json:"claimed_bump"`
	SemanticFloor string         `json:"semantic_floor"`
	Effective     string         `json:"effective"`
	Own           string         `json:"own"`
	Blast         string         `json:"blast"`
	Strategy      string         `json:"strategy"`
	Iteration     uint64         `json:"iteration"`
	PredicateType string         `json:"predicate_type"`
	Signer        string         `json:"attestation_signer,omitempty"`
	StoredRefs    []string       `json:"stored_refs,omitempty"`
	Report        *verify.Report `json:"report"`
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
