// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/semver-trust/semver-trust-go/internal/verify"
)

// newVerifyCmd is the `verify` subcommand: it walks FROM..TO and reports the
// provenance and effective trust per spec §10 steps 1–7. Steps 8–9 (decide,
// emit) belong to `release` (GO-042).
func newVerifyCmd() *cobra.Command {
	var (
		repoPath           string
		from               string
		to                 string
		policyPath         string
		allowedSigners     string
		attestationSigners string
		component          string
		verifyTime         string
		jsonOut            bool
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
protects the system, §5.4).`,
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

			report, err := verify.Verify(verify.Options{
				RepoPath:               repoPath,
				From:                   from,
				To:                     to,
				PolicyPath:             policyPath,
				AllowedSignersPath:     allowedSigners,
				AttestationSignersPath: attestationSigners,
				Component:              component,
				VerifyTime:             at,
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
	f.StringVar(&from, "from", "", "previous release tag; empty = first release (root..TO)")
	f.StringVar(&to, "to", "HEAD", "proposed release commit (revision)")
	f.StringVar(&policyPath, "policy", ".semver-trust/policy.toml", "policy file path within TO's tree")
	f.StringVar(&allowedSigners, "allowed-signers", "", "filesystem allowed-signers override; empty resolves the policy's identity.human.allowed_signers from TO's tree")
	f.StringVar(&attestationSigners, "attestation-signers", "", "filesystem attestation-signer registry; empty means reviews cannot be verified and classify none")
	f.StringVar(&component, "component", "", "workspace component to headline; empty = single/root component")
	f.StringVar(&verifyTime, "verify-time", "", "verification instant (RFC3339); empty = now at the CLI boundary")
	f.BoolVar(&jsonOut, "json", false, "emit a structured JSON report instead of the human table")
	return cmd
}
