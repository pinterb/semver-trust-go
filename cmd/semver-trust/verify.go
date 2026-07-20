// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/semver-trust/semver-trust-go/internal/chain"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

// newVerifyCmd is the `verify` subcommand: it walks FROM..TO and reports the
// provenance and effective trust per spec §10 steps 1–7. Steps 8–9 (decide,
// emit) belong to `release` (GO-042).
func newVerifyCmd() *cobra.Command {
	var (
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
		chainHead           bool
		jsonOut             bool
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a release range's provenance and trust (spec §10 steps 1–7)",
		Long: `verify walks the commit range FROM..TO (root..TO for a first release),
loads the policy from TO's tree, verifies every commit's signature and any
covering review attestation, applies derivation proofs, and aggregates trust
into per-scope own floors and effective trust over the workspace graph.

It fails closed: any commit that cannot be verified end-to-end, or a meta-path
commit below the required level, aborts the run with a one-line reason naming
the spec §10 step that failed (unverifiable is never T0, §5.2; the config
protects the system, §5.4).

A first release (no --from) anchors at the adoption boundary when the policy
declares one ([policy] adoption_boundary, ADR-026): history before the
boundary is exempt and makes no claim, and the report discloses the boundary
in both renderings. The boundary is policy-pinned by design — there is no
flag for it, because a CLI-supplied boundary could be moved by whoever runs
the verifier.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The verification clock is read once, here at the process
			// boundary, and injected into every internal call (ADR-018 keeps
			// internal/* free of time.Now). --verify-time overrides it.
			at := time.Now()
			if verifyTime != "" {
				parsed, err := time.Parse(time.RFC3339, verifyTime)
				if err != nil {
					return err
				}
				at = parsed
			}

			var descriptor *chain.BootstrapDescriptor
			if bootstrapDescriptor != "" {
				d, derr := chain.LoadBootstrapDescriptor(bootstrapDescriptor, repoPath)
				if derr != nil {
					return fmt.Errorf("verify refused: %w", derr)
				}
				descriptor = d
			}

			// --chain-head reports the AUTHENTICATED accepted chain head (§7.5/ADR-029)
			// rather than verifying a proposed interval: it fresh-verifies every stored
			// release/v0.2 and reports the unique head's recorded decision. It is the
			// answer to "what release IS the verified accepted head, and what trust did
			// it attest?" — for callers (e.g. a release badge) that must read the head's
			// trust from the verified object, not an unverified store blob. Verifying at
			// the head's own commit is otherwise promotion_required (an empty interval).
			if chainHead {
				if descriptor == nil {
					return fmt.Errorf("verify refused: --chain-head requires --bootstrap-descriptor (the authenticated v0.10 chain authority)")
				}
				opts := verify.Options{
					RepoPath:               repoPath,
					To:                     to,
					PolicyPath:             policyPath,
					AllowedSignersPath:     allowedSigners,
					AttestationSignersPath: attestationSigners,
					GPGKeyringPath:         gpgKeyring,
					Component:              component,
					VerifyTime:             at,
					Bootstrap:              descriptor,
				}
				// Authenticate the descriptor against TO's tree and reject trust-material
				// overrides BEFORE trusting the store — this path bypasses the interval
				// pipeline's checkPolicyTransition, so it must do the §5.4/ADR-028 binding
				// itself, or a stale/tampered descriptor could report a head.
				if aerr := verify.AuthenticateBootstrapTree(opts); aerr != nil {
					return fmt.Errorf("verify refused: %w", aerr)
				}
				av, aerr := verify.AttestationVerifier(opts)
				if aerr != nil {
					return fmt.Errorf("verify refused: %w", aerr)
				}
				if av == nil {
					return fmt.Errorf("verify refused: the policy declares no attestation signers, so the accepted chain cannot be verified (§9)")
				}
				// Bind the reported head to THIS descriptor: the genesis release must
				// record it as the bootstrap authority (§5.4/ADR-028), not merely share
				// the repository/component. descriptor.Digest() is the descriptor's
				// authority identity.
				head, herr := chain.AcceptedChainHeadBoundTo(repoPath, descriptor.Repository, descriptor.Component, descriptor.Digest(), av, at)
				if herr != nil {
					return fmt.Errorf("verify refused: %w", herr)
				}
				if head == nil {
					return fmt.Errorf("verify refused: no accepted release/v0.2 chain head for component %q (none published yet)", descriptor.Component)
				}
				return writeChainHead(cmd.OutOrStdout(), head, jsonOut)
			}

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
				Bootstrap:              descriptor,
			})
			if err != nil {
				return err
			}

			if jsonOut {
				return report.WriteJSON(cmd.OutOrStdout())
			}
			return report.WriteText(cmd.OutOrStdout())
		},
	}

	f := cmd.Flags()
	f.StringVar(&repoPath, "repo", ".", "repository to verify")
	f.StringVar(&from, "from", "", "previous release tag; empty = first release (root..TO, or boundary..TO under a policy-declared adoption_boundary, ADR-026)")
	f.StringVar(&to, "to", "HEAD", "proposed release commit (revision)")
	f.StringVar(&policyPath, "policy", ".semver-trust/policy.toml", "policy file path within TO's tree")
	f.StringVar(&allowedSigners, "allowed-signers", "", "filesystem allowed-signers override; empty resolves the policy's identity.human.allowed_signers from TO's tree")
	f.StringVar(&attestationSigners, "attestation-signers", "", "filesystem attestation-signer registry; overrides the policy. Empty resolves [identity] attestation_signers from TO's tree (§9); if the policy declares none either, reviews cannot be verified and classify none")
	f.StringVar(&gpgKeyring, "gpg-keyring", "", "armored OpenPGP public keyring for GPG-signed commits; overrides the policy. Empty resolves [identity.human] gpg_keyring from TO's tree (§9); if the policy declares none either, the GPG key family is unverifiable and fails closed")
	f.StringVar(&component, "component", "", "workspace component to headline; empty = single/root component")
	f.StringVar(&verifyTime, "verify-time", "", "verification instant (RFC3339); empty = now at the CLI boundary")
	f.StringVar(&bootstrapDescriptor, "bootstrap-descriptor", "", "out-of-band v0.10 bootstrap descriptor (§5.2/§5.4, ADR-027/028); when supplied, the release interval is the authenticated exact interval (inception root..TO, or adoption including the boundary) rather than FROM..TO. Must be supplied from outside the repository")
	f.BoolVar(&chainHead, "chain-head", false, "instead of verifying an interval, fresh-verify the v0.10 chain and report the accepted chain head's tag and recorded effective trust (§7.5/ADR-029); requires --bootstrap-descriptor")
	f.BoolVar(&jsonOut, "json", false, "emit a structured JSON report instead of the human table")
	return cmd
}

// writeChainHead renders the accepted chain head (--chain-head): the verified head's
// tag, target commit, recorded effective trust, and resulting-state digest.
func writeChainHead(w io.Writer, head *chain.Predecessor, jsonOut bool) error {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]string{
			"tag":                    head.Tag(),
			"to_commit":              head.To(),
			"effective":              head.Effective(),
			"resulting_state_digest": head.ResultingStateDigest(),
		})
	}
	_, err := fmt.Fprintf(w, "accepted chain head: %s -> %s (effective %s, §7.5/ADR-029)\n",
		head.Tag(), head.To(), head.Effective())
	return err
}
