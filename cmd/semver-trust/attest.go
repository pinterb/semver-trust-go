// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/semver-trust/semver-trust-go/conformance"
	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// newAttestCmd is the `attest` command group: emitting signed SemVer-Trust
// attestations (the production side of what `verify` consumes).
func newAttestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Emit signed SemVer-Trust attestations",
	}
	cmd.AddCommand(newAttestReviewCmd())
	return cmd
}

// newAttestReviewCmd is `attest review`: the post-hoc review machinery of
// spec §4.3/§7.3 (Appendix A step 3). A reviewer reviews commits, this
// command emits the signed review attestation as an ADR-022 DSSE envelope
// and stores it under each covered commit, and `verify` then lifts those
// commits' levels per §3.2.
func newAttestReviewCmd() *cobra.Command {
	var (
		repoPath      string
		commits       []string
		from          string
		to            string
		reviewer      string
		reviewerClass string
		verdict       string
		pr            string
		mergeStrategy string
		keyPath       string
		timestamp     string
		storeEnvelope bool
		outPath       string
	)

	cmd := &cobra.Command{
		Use:   "review",
		Short: "Emit a signed review attestation over commits (spec §4.3)",
		Long: `attest review emits a §4.3 review attestation: an in-toto Statement whose
subjects are the covered commit SHAs, signed per ADR-022 as an OpenSSH SSHSIG
over the DSSE pre-authentication encoding in the attestation namespace.

The payload is schema-validated before signing (signed bytes are frozen; an
invalid payload is refused, never signed), and the finished envelope is
verified before it is output. By default the envelope is stored in the
repository under refs/attestations/<sha>/... for every covered commit, where
verify's per-commit lookup finds it.

Commits come from --commits and/or a --from/--to range (the same two-dot
semantics verify walks). The signing key must be enrolled — for the
attestation namespace — in the registry verify is given via
--attestation-signers, or the attestation verifies as an unknown signer and
aborts the run.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The review timestamp is read once, here at the process boundary,
			// and injected (ADR-018 keeps internal/* free of time.Now).
			ts := time.Now().UTC()
			if timestamp != "" {
				parsed, err := time.Parse(time.RFC3339, timestamp)
				if err != nil {
					return fmt.Errorf("--timestamp: %w", err)
				}
				ts = parsed
			}

			subjects, err := resolveSubjects(repoPath, commits, from, to)
			if err != nil {
				return err
			}
			if len(subjects) == 0 {
				return errors.New("no commits to attest: give --commits and/or --from/--to")
			}

			keyBytes, err := os.ReadFile(keyPath)
			if err != nil {
				return fmt.Errorf("--key: %w", err)
			}
			signer, err := sshsig.LoadSigner(keyBytes)
			if err != nil {
				return err
			}
			reviewSchema, err := conformance.Vector("schemas/review-v0.1.json")
			if err != nil {
				return err
			}
			emitter, err := attest.NewReviewEmitter(signer, reviewSchema)
			if err != nil {
				return err
			}

			emission, err := emitter.Emit(attest.ReviewInput{
				Subjects: subjects,
				Reviewers: []attest.Reviewer{{
					Identity: reviewer,
					Class:    reviewerClass,
					Verdict:  verdict,
				}},
				PullRequest:   pr,
				MergeStrategy: mergeStrategy,
				Timestamp:     ts,
			})
			if err != nil {
				return err
			}

			var refs []string
			if storeEnvelope {
				refs, err = attest.StoreForSubjects(attest.GitRefStore{Path: repoPath}, subjects, emission.Envelope)
				if err != nil {
					return err
				}
			}
			if outPath != "" {
				if err := os.WriteFile(outPath, emission.Envelope, 0o644); err != nil {
					return fmt.Errorf("--out: %w", err)
				}
			}

			w := &errWriter{w: cmd.OutOrStdout()}
			w.printf("review attestation emitted (predicate %s)\n", attest.PredicateReview)
			w.printf("  reviewer: %s (%s, %s)\n", reviewer, reviewerClass, verdict)
			w.printf("  signer:   %s\n", emission.KeyID)
			w.printf("  subjects:\n")
			for i, s := range subjects {
				w.printf("    %s\n", s)
				if i < len(refs) {
					w.printf("      stored: %s\n", refs[i])
				}
			}
			if !storeEnvelope {
				w.printf("  stored:   no (--store=false)\n")
			}
			if outPath != "" {
				w.printf("  written:  %s\n", outPath)
			}
			return w.err
		},
	}

	f := cmd.Flags()
	f.StringVar(&repoPath, "repo", ".", "repository holding the commits (and the attestation store)")
	f.StringSliceVar(&commits, "commits", nil, "commit SHAs (or revisions) the review covers, comma-separated")
	f.StringVar(&from, "from", "", "range start (exclusive); with --from/--to the covered commits are the FROM..TO range")
	f.StringVar(&to, "to", "", "range end (inclusive); defaults to HEAD when a range is requested")
	f.StringVar(&reviewer, "reviewer", "", "verified reviewer identity (required)")
	f.StringVar(&reviewerClass, "reviewer-class", "human", "reviewer class: human or agent")
	f.StringVar(&verdict, "verdict", "approved", "review verdict: approved, changes_requested, or commented")
	f.StringVar(&pr, "pr", "", "pull/merge request reference, URL or id (required)")
	f.StringVar(&mergeStrategy, "merge-strategy", "merge", "merge strategy: merge, squash, or rebase")
	f.StringVar(&keyPath, "key", "", "OpenSSH private key to sign with (required; passphrase-protected keys unsupported)")
	f.StringVar(&timestamp, "timestamp", "", "review timestamp (RFC3339); empty = now at the CLI boundary")
	f.BoolVar(&storeEnvelope, "store", true, "store the envelope under refs/attestations/<sha>/... for each subject")
	f.StringVar(&outPath, "out", "", "also write the envelope JSON to this file")
	for _, required := range []string{"reviewer", "pr", "key"} {
		if err := cmd.MarkFlagRequired(required); err != nil {
			panic(err)
		}
	}
	return cmd
}

// resolveSubjects turns --commits entries and an optional --from/--to range
// into a deduplicated, order-preserving list of full commit SHAs. Every
// entry resolves through the repository, so tags and abbreviated hashes
// never leak into storage keys or attestation subjects.
func resolveSubjects(repoPath string, commits []string, from, to string) ([]string, error) {
	var subjects []string
	seen := map[string]bool{}
	add := func(sha string) {
		if !seen[sha] {
			seen[sha] = true
			subjects = append(subjects, sha)
		}
	}

	for _, rev := range commits {
		sha, err := vcs.ResolveCommit(repoPath, rev)
		if err != nil {
			return nil, fmt.Errorf("--commits: %w", err)
		}
		add(sha)
	}
	if from != "" || to != "" {
		rangeTo := to
		if rangeTo == "" {
			rangeTo = "HEAD"
		}
		rcs, err := vcs.Range(repoPath, from, rangeTo)
		if err != nil {
			return nil, err
		}
		for _, rc := range rcs {
			add(rc.Hash)
		}
	}
	return subjects, nil
}
