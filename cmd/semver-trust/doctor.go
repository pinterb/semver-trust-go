// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/semver-trust/semver-trust-go/internal/chain"
	"github.com/semver-trust/semver-trust-go/internal/pathfence"
	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/preflight"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// newDoctorCmd is the `doctor` subcommand: a read-only diagnostic that surfaces,
// before you commit or release, the mistakes verification would later abort or
// mis-price — using the same functions verify uses. It never writes (ADR-037),
// and it ends every run by printing the real `verify` invocation: doctor is the
// on-ramp to verify, never a replacement, and is not meant to be wired into CI.
func newDoctorCmd() *cobra.Command {
	var (
		repoPath       string
		personaStr     string
		policyPath     string
		descriptorPath string
		staged         bool
		commitRev      string
		messageF       string
		atStr          string
		strict         bool
		jsonOut        bool
	)

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose this environment before verification (read-only)",
		Long: `doctor runs read-only checks that surface, at authoring time, the mistakes
verification would later abort or mis-price — an unenrolled signing key, a
malformed registry, a missing trailer, a policy that will not parse — each with
the exact fix. It writes nothing and ends by printing the verify invocation it
preempts.

Persona (maintainer/contributor/agent) selects the check-set and is auto-detected
for humans (a principal enrolled in attestation_signers is a maintainer); pass
--persona to override. --persona agent is the one mode an agent is sanctioned to
run and restricts the run to a side-effect-free subset.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The clock is read once here at the process boundary (ADR-018).
			at := time.Now()
			if atStr != "" {
				parsed, err := time.Parse(time.RFC3339, atStr)
				if err != nil {
					return err
				}
				at = parsed
			}

			git, err := preflight.LoadGitConfig(repoPath)
			if err != nil {
				return err
			}

			// Load the working-tree policy (doctor diagnoses the tree you are about
			// to commit); a parse error is reported by the policy/parse check. The
			// path is fenced before any filesystem read: --policy (or a hostile
			// checkout) could contain ".." or a symlink, and doctor must not read
			// outside the repository even for a read-only diagnostic (ADR-039).
			var (
				pol    *policy.Policy
				polRaw []byte
				polErr error
			)
			if abs, ferr := pathfence.Resolve(repoPath, policyPath); ferr != nil {
				polErr = ferr
			} else if data, readErr := os.ReadFile(abs); readErr == nil {
				polRaw = data
				pol, polErr = policy.Parse(polRaw)
			} else if !errors.Is(readErr, os.ErrNotExist) {
				// A present-but-unreadable policy (permission denied, is a
				// directory) is a more precise diagnostic than "no policy at …";
				// a plain absence falls through to that generic message.
				polErr = readErr
			}

			persona, err := resolvePersona(personaStr, repoPath, pol)
			if err != nil {
				return err
			}

			// The bootstrap descriptor is optional out-of-band trust material
			// (ADR-027/028); when supplied, chain/chain-head projects the accepted
			// chain head from it. A supplied-but-unloadable descriptor is a hard
			// error — a silent nil would make the check quietly SKIP.
			var descriptor *chain.BootstrapDescriptor
			if descriptorPath != "" {
				descriptor, err = chain.LoadBootstrapDescriptor(descriptorPath, repoPath)
				if err != nil {
					return fmt.Errorf("--bootstrap-descriptor %q: %w", descriptorPath, err)
				}
			}

			// Resolve --message (a commit-message file, or "-" for stdin) to its
			// content here at the boundary; the simulate/classify check stays
			// I/O-free. --message is a user-supplied path, not a policy-named repo
			// path, so it is read directly (not fenced).
			var msgBytes []byte
			if messageF == "-" {
				if msgBytes, err = io.ReadAll(cmd.InOrStdin()); err != nil {
					return err
				}
			} else if messageF != "" {
				if msgBytes, err = os.ReadFile(messageF); err != nil {
					return fmt.Errorf("--message %q: %w", messageF, err)
				}
			}

			env := &preflight.Env{
				Repo:       repoPath,
				Persona:    persona,
				At:         at,
				Policy:     pol,
				PolicyRaw:  polRaw,
				PolicyPath: policyPath,
				PolicyErr:  polErr,
				Git:        git,
				Descriptor: descriptor,
				Staged:     staged,
				Commit:     commitRev,
				Message:    msgBytes,
			}

			report := preflight.Run(env, preflight.Catalog())

			if jsonOut {
				if err := report.WriteJSON(cmd.OutOrStdout()); err != nil {
					return err
				}
			} else if err := report.Render(cmd.OutOrStdout(), strict); err != nil {
				return err
			}

			// A FAIL (or, under --strict, a WARN) yields a non-zero exit via the
			// returned error — the sole exit-code path (main maps it to os.Exit(1)).
			if report.HasFail() || (strict && report.HasWarn()) {
				return errors.New("doctor: one or more checks did not pass")
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&repoPath, "repo", ".", "repository to diagnose")
	f.StringVar(&personaStr, "persona", "", "maintainer|contributor|agent (default: auto-detected for humans)")
	f.StringVar(&policyPath, "policy", ".semver-trust/policy.toml", "policy file path within the repository")
	f.StringVar(&descriptorPath, "bootstrap-descriptor", "", "out-of-band bootstrap descriptor (enables chain/chain-head)")
	f.BoolVar(&staged, "staged", false, "diagnose the staged changes (simulate checks)")
	f.StringVar(&commitRev, "commit", "", "diagnose a specific commit revision")
	f.StringVar(&messageF, "message", "", "diagnose a commit-message file (- for stdin)")
	f.StringVar(&atStr, "at", "", "diagnosis instant (RFC3339); empty = now at the CLI boundary")
	f.BoolVar(&strict, "strict", false, "promote WARN to FAIL")
	f.BoolVar(&jsonOut, "json", false, "emit a structured JSON report instead of the human table")
	return cmd
}

// resolvePersona maps --persona (or auto-detection) to a preflight.Persona. Auto:
// the tagger email enrolled in the policy's attestation_signers registry ⇒
// maintainer, else contributor (a side-effect-free, disclosed default). --persona
// agent is never auto-detected: it is a contract requested explicitly.
func resolvePersona(personaStr, repo string, pol *policy.Policy) (preflight.Persona, error) {
	switch personaStr {
	case "maintainer":
		return preflight.Maintainer, nil
	case "contributor":
		return preflight.Contributor, nil
	case "agent":
		return preflight.Agent, nil
	case "":
		// auto-detect below
	default:
		return 0, fmt.Errorf("unknown --persona %q (maintainer|contributor|agent)", personaStr)
	}

	_, email, err := vcs.Tagger(repo)
	if err != nil || email == "" {
		return preflight.Contributor, nil
	}
	if pol == nil || pol.Identity.AttestationSigners == "" {
		return preflight.Contributor, nil
	}
	// Fence the policy-declared attestation_signers path before reading it: a
	// hostile repo could point it outside the tree. A refusal (or any read error)
	// falls back to the contributor default rather than reading outside the repo.
	abs, ferr := pathfence.Resolve(repo, pol.Identity.AttestationSigners)
	if ferr != nil {
		return preflight.Contributor, nil
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return preflight.Contributor, nil
	}
	signers, err := sshsig.ParseAllowedSigners(data)
	if err != nil {
		return preflight.Contributor, nil
	}
	for _, s := range signers {
		for _, p := range s.Principals {
			if p == email {
				return preflight.Maintainer, nil
			}
		}
	}
	return preflight.Contributor, nil
}
