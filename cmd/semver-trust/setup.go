// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/gitconfig"
	"github.com/semver-trust/semver-trust-go/internal/pathfence"
	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/setup"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

// newSetupCmd is the `setup` subcommand: it configures THIS clone's git for
// semver-trust and nothing else — repo-local .git/config keys through the git binary
// (ADR-042), never --global, never the working tree, never a hook (the committed
// .githooks/commit-msg + a printed core.hooksPath line do that). It obeys the ADR-039
// writer contract: all-or-nothing conflicts, --dry-run mutates nothing and prints the
// exact git config commands, and every run ends with a reversal receipt.
func newSetupCmd() *cobra.Command {
	var (
		repoPath   string
		remote     string
		signingKey string
		gpgKey     string
		policyPath string
		force      bool
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Configure this clone's git for semver-trust (repo-local config only)",
		Long: `setup writes only this clone's repo-local git configuration — gpg.format,
user.signingkey, commit.gpgsign, commit.template (if .gitmessage exists),
gpg.ssh.allowedSignersFile (SSH mode), and an attestation fetch refspec — through the
git binary (ADR-042). It never writes --global, the working tree, a push refspec, or
a hook: the committed .githooks/commit-msg plus a one-time 'git config core.hooksPath
.githooks' do the hook job without the trust tool writing executable code.

It is all-or-nothing (ADR-039): any key already set to a different value fails the run
listing every conflict, writing nothing. --force overwrites, except user.signingkey,
which is never overwritten by a flag. --dry-run changes nothing and prints the exact
git config commands. Every run ends by printing the commands that reverse it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if remote == "" {
				remote = "origin"
			}
			cfg, err := gitconfig.Load(repoPath)
			if err != nil {
				return err
			}
			git := gitconfig.Git{Path: cfg.GitPath, Repo: repoPath}

			// Gather the injected facts the pure planner runs against.
			currents, err := setup.ReadCurrents(git)
			if err != nil {
				return fmt.Errorf("setup: reading current config: %w", err)
			}
			remoteURL, err := git.RemoteURL(remote)
			if err != nil {
				return fmt.Errorf("setup: reading remote %q: %w", remote, err)
			}
			fetchRefspecs, err := git.FetchRefspecs(remote)
			if err != nil {
				return fmt.Errorf("setup: reading remote %q fetch: %w", remote, err)
			}

			env := setup.Env{
				Config:              cfg,
				Current:             currents,
				SigningKey:          signingKey,
				GPGSigningKey:       gpgKey,
				Remote:              remote,
				RemoteURL:           remoteURL,
				RemoteFetchRefspecs: fetchRefspecs,
				GitmessageExists:    fileExists(repoPath, ".gitmessage"),
				Force:               force,
				Euid:                os.Geteuid(),
				GitDirEnv:           os.Getenv("GIT_DIR") != "",
				GitConfigEnv:        gitConfigEnvSet(),
			}

			// The environment echo is the FIRST line of EVERY run, printed immediately
			// after the git facts are loaded — BEFORE the policy, the key, or the plan —
			// so EVERY refusal (a malformed policy, a fenced path, or a conflict / bare /
			// root / env / two-key refusal) still shows which repo / gitdir / git-binary /
			// remote it acted on.
			w := &errWriter{w: cmd.OutOrStdout()}
			printEnvEcho(w, env)

			// A policy is optional (setup configures git, not trust material), but a
			// PRESENT policy that cannot be loaded is surfaced, not silently dropped —
			// a dropped policy would skip the ADR-022 cross-check it declares.
			pol, err := loadSetupPolicy(repoPath, policyPath)
			if err != nil {
				return err
			}
			env.Policy = pol

			// SSH mode: fingerprint the offered key (for the ADR-022 cross-check) and
			// resolve the allowed-signers registry to wire (fenced).
			if signingKey != "" {
				pub, perr := readPubKey(expandTilde(signingKey))
				if perr != nil {
					return fmt.Errorf("--signing-key %q: %w", signingKey, perr)
				}
				env.SigningKeyFingerprint = ssh.FingerprintSHA256(pub)
				if env.AllowedSignersPath, env.AllowedSignersExists, err = resolveAllowedSigners(repoPath, pol); err != nil {
					return err
				}
			}
			env.AttestationSignersDeclared, env.AttestationFingerprints, env.AttestationReadErr = attestationFacts(repoPath, pol)

			plan, err := setup.Compute(env)
			if err != nil {
				return err // a refusal — the echo is already on stdout; cobra prints this on stderr
			}

			return renderPlan(w, plan, dryRun, git)
		},
	}

	f := cmd.Flags()
	f.StringVar(&repoPath, "repo", ".", "repository to configure")
	f.StringVar(&remote, "remote", "origin", "remote to configure the attestation fetch refspec on")
	f.StringVar(&signingKey, "signing-key", "", "path to an SSH public key to sign commits with")
	f.StringVar(&gpgKey, "gpg-signing-key", "", "a GPG key id to sign commits with")
	f.StringVar(&policyPath, "policy", ".semver-trust/policy.toml", "policy file path within the repository")
	f.BoolVar(&force, "force", false, "overwrite conflicting config (never user.signingkey)")
	f.BoolVar(&dryRun, "dry-run", false, "print the git config commands; change nothing")
	return cmd
}

// printEnvEcho writes the environment echo — the FIRST line of every run, printed
// before the plan is computed so it appears on refusals too: the audit trail of which
// repo, gitdir, git binary (the PATH-hijack surface), and remote/URL (SU-8) the run
// acted on, plus the linked-worktree shared-config disclosure.
func printEnvEcho(w *errWriter, env setup.Env) {
	url := env.RemoteURL
	if url == "" {
		url = "(no url)"
	}
	w.printf("setup: repo %s  gitdir %s  git %s  remote %s (%s)\n",
		orDot(env.Config.TopLevel), orDot(env.Config.GitDir), env.Config.GitPath, env.Remote, url)
	if isLinkedWorktree(env.Config) {
		w.printf("note: linked worktree — repo-local config is shared across all worktrees of this repository\n")
	}
}

// renderPlan writes the plan and either the dry-run commands or the applied receipt.
// The environment echo has already been printed (printEnvEcho, before Compute).
func renderPlan(w *errWriter, plan *setup.Plan, dryRun bool, git gitconfig.Git) error {
	for _, warn := range plan.Warnings {
		w.printf("warn: %s\n", warn)
	}

	w.printf("\n")
	for _, c := range plan.Changes {
		switch c.Action {
		case setup.ActionForced:
			w.printf("  %-8s %s = %s  (was %s)\n", "force", c.Key, c.Desired, c.Current)
		default:
			w.printf("  %-8s %s = %s\n", c.Action, c.Key, c.Desired)
		}
	}
	if plan.Fetch != nil {
		if plan.Fetch.Already {
			w.printf("  %-8s remote.%s.fetch %s\n", setup.ActionOK, plan.Fetch.Remote, plan.Fetch.Refspec)
		} else {
			w.printf("  %-8s remote.%s.fetch += %s\n", "add", plan.Fetch.Remote, plan.Fetch.Refspec)
		}
	}

	if dryRun {
		w.printf("\n--dry-run: nothing was changed. these are the exact commands to run:\n")
		for _, line := range plan.GitCommands() {
			w.printf("  %s\n", line)
		}
		if len(plan.GitCommands()) == 0 {
			w.printf("  (already fully configured — nothing to do)\n")
		}
		return w.err
	}

	if err := plan.Apply(git); err != nil {
		return err
	}
	rev := plan.ReverseCommands()
	if len(rev) == 0 {
		w.printf("\nalready fully configured — nothing to change.\n")
		return w.err
	}
	w.printf("\napplied. to reverse this setup:\n")
	for _, line := range rev {
		w.printf("  %s\n", line)
	}
	return w.err
}

// loadSetupPolicy fences + parses the working-tree policy. A policy is optional — a
// genuine absence (os.ErrNotExist) is (nil, nil) — but a PRESENT policy that cannot be
// loaded (a fence refusal, a read error, or a parse error) is surfaced, never dropped:
// silently discarding a policy that declares attestation_signers would skip the ADR-022
// two-key cross-check it governs.
func loadSetupPolicy(repo, policyPath string) (*policy.Policy, error) {
	abs, err := pathfence.Resolve(repo, policyPath)
	if err != nil {
		return nil, fmt.Errorf("setup: policy path refused: %w", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // no policy → setup configures git, not trust material
		}
		return nil, fmt.Errorf("setup: cannot read policy %s: %w", policyPath, err)
	}
	pol, err := policy.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("setup: policy does not parse: %w", err)
	}
	return pol, nil
}

// resolveAllowedSigners returns the allowed-signers registry path to wire into
// gpg.ssh.allowedSignersFile (from the policy, else the convention) and whether that
// file exists — set only when present (SSH mode). The policy-named path is FENCED
// before it is touched: a hostile "../../outside/allowed_signers" or a symlink must
// not point local git's signature-verification authority outside the repository. The
// value written back is the safe repo-relative string, only after validation.
func resolveAllowedSigners(repo string, pol *policy.Policy) (path string, exists bool, err error) {
	path = ".semver-trust/allowed_signers"
	if pol != nil && pol.Identity.Human.AllowedSigners != "" {
		path = pol.Identity.Human.AllowedSigners
	}
	abs, ferr := pathfence.Resolve(repo, path)
	if ferr != nil {
		return "", false, fmt.Errorf("setup: allowed_signers path refused: %w", ferr)
	}
	info, serr := os.Stat(abs)
	return path, serr == nil && !info.IsDir(), nil
}

// attestationFacts reports whether the policy declares attestation_signers, the
// SHA256 fingerprints enrolled there, and any read error (a declared-but-unreadable
// registry fails closed in the planner's ADR-022 cross-check).
func attestationFacts(repo string, pol *policy.Policy) (declared bool, fps []string, readErr error) {
	if pol == nil || pol.Identity.AttestationSigners == "" {
		return false, nil, nil
	}
	abs, err := pathfence.Resolve(repo, pol.Identity.AttestationSigners)
	if err != nil {
		return true, nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return true, nil, err
	}
	signers, err := sshsig.ParseAllowedSigners(data)
	if err != nil {
		return true, nil, err
	}
	for _, s := range signers {
		if s.Key != nil {
			fps = append(fps, ssh.FingerprintSHA256(s.Key))
		}
	}
	return true, fps, nil
}

// gitConfigEnvSet reports whether any GIT_CONFIG* variable is set — these redirect
// git config to an ambiguous target, so setup refuses to write under them (SU-7).
func gitConfigEnvSet() bool {
	for _, k := range []string{"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// isLinkedWorktree reports whether the clone is a linked worktree, where a repo-local
// config write is shared across all worktrees — worth disclosing. A linked worktree's
// git-dir lives under the main repository's .git/worktrees/.
func isLinkedWorktree(cfg *gitconfig.Config) bool {
	return strings.Contains(filepath.ToSlash(cfg.GitDir), "/worktrees/")
}

func fileExists(repo, rel string) bool {
	info, err := os.Stat(filepath.Join(repo, rel))
	return err == nil && !info.IsDir()
}

// expandTilde expands a leading ~ in a user-supplied key path (the shell usually does
// this, but a quoted path reaches us literally).
func expandTilde(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
		}
	}
	return path
}

func orDot(s string) string {
	if s == "" {
		return "."
	}
	return s
}
