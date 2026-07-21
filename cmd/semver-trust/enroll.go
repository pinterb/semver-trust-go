// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/enroll"
	"github.com/semver-trust/semver-trust-go/internal/pathfence"
	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// newEnrollCmd is the `enroll` subcommand: it turns a key into the byte-exact
// registry line the human commits. Print-by-default puts that material in front of
// the person at the accountability moment (ADR-038); --write appends it to the
// working-tree registry under the atomic writer contract (ADR-039). It never stages,
// commits, or signs — the accountability act stays a human's signed commit.
func newEnrollCmd() *cobra.Command {
	var (
		repoPath   string
		email      string
		commitKey  string
		attestKey  string
		policyPath string
		write      bool
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Generate a trust-material enrollment line (read-only by default)",
		Long: `enroll formats a key into the byte-exact registry line the human commits, and
prints it — raw registry bytes on stdout, all guidance on stderr. It never stages,
commits, or signs: the tool generates and validates; the human enrolls, commits,
and signs (ADR-038).

The principal defaults from git user.email (the same identity your commits carry),
so the registry principal equals your commit identity by construction. Namespaces
come from compiled constants, so the "git" / attestation namespace can never be
mistyped.

--write appends the line to the working-tree registry named by the policy, under
the atomic writer contract (ADR-039): a repo-relative path fence, no directory
creation, a strict re-parse of the whole result, and a temp-file + fsync + rename.
--dry-run makes zero filesystem changes and prints exactly what --write would do.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The clock is read once here at the process boundary (ADR-018); it feeds
			// the enrollment self-check's validity window.
			at := time.Now()

			principal, principalNote, err := resolvePrincipal(email, repoPath)
			if err != nil {
				return err
			}

			pol, err := loadEnrollPolicy(repoPath, policyPath)
			if err != nil {
				return err
			}

			targets := 0
			if commitKey != "" {
				targets++
			}
			if attestKey != "" {
				targets++
			}
			if targets == 0 {
				return errors.New("enroll: at least one of --commit-key or --attest-key is required")
			}

			// --write is atomic per file, but a batch of registries is NOT: a
			// cross-file transaction cannot be provided by temp+rename, so a second
			// target's write failure would leave the first registry changed. Rather
			// than fake all-or-nothing, --write handles exactly one registry — the
			// human runs a separate --write per key so each atomic write stands alone.
			// --dry-run previews the real --write, so it enforces the SAME restriction:
			// a multi-target write is refused whether or not it is a dry run, so the
			// preview never advertises an operation the real path would reject.
			if (write || dryRun) && targets > 1 {
				return errors.New("enroll: --write handles one registry at a time (each write is atomic per file; a batch is not) — run a separate `enroll ... --write` per key")
			}

			// Build every requested enrollment in memory first.
			var pending []enrollment
			if commitKey != "" {
				e, err := buildSSHTarget(repoPath, commitKey, "--commit-key",
					pol.Identity.Human.AllowedSigners, "allowed_signers",
					pol.Identity.AttestationSigners, vcs.GitSSHNamespace, principal, at)
				if err != nil {
					return err
				}
				pending = append(pending, e)
			}
			if attestKey != "" {
				e, err := buildSSHTarget(repoPath, attestKey, "--attest-key",
					pol.Identity.AttestationSigners, "attestation_signers",
					pol.Identity.Human.AllowedSigners, attest.Namespace, principal, at)
				if err != nil {
					return err
				}
				pending = append(pending, e)
			}

			// ADR-040 across the PENDING set: each target's on-disk cross-registry
			// check cannot see the other target's not-yet-written mutation, so one
			// invocation could otherwise enroll the same key as both a commit and an
			// attestation signer. Refuse a fingerprint that appears in more than one
			// target — commit and attestation keys must be distinct.
			seen := map[string]string{}
			for _, e := range pending {
				if prev, dup := seen[e.result.Fingerprint]; dup {
					return fmt.Errorf("enroll: the same key is targeted by %s and %s — commit and attestation keys must be distinct (ADR-022/040)", prev, e.flag)
				}
				seen[e.result.Fingerprint] = e.flag
			}

			so := &errWriter{w: cmd.OutOrStdout()}
			se := &errWriter{w: cmd.ErrOrStderr()}

			// Print-by-default: ONLY the byte-exact material on stdout (safe for `>>`).
			for _, e := range pending {
				so.println(e.result.Line)
			}

			// All guidance, disclosure, and warnings on stderr.
			se.printf("\nprincipal: %s %s\n", principal, principalNote)
			for _, e := range pending {
				se.printf("%s → %s  (fingerprint %s)\n", e.flag, e.relPath, e.result.Fingerprint)
				if e.result.Warn != "" {
					se.printf("  warn: %s\n", e.result.Warn)
				}
			}
			se.println("\nThe tool never stages, commits, or signs (ADR-038). To enroll, either:")
			se.println("  • paste the printed line into your enrollment PR;")
			se.println("  • redirect THIS command's output into the registry (never retype the line —")
			se.println(`    shell quoting eats namespaces="…"); or`)
			se.println("  • re-run with --write to append it atomically.")
			se.println("Then commit the trust material alone — path-scoped, never `git add -A` (§6):")
			se.println("  git add .semver-trust && git commit -S")

			switch {
			case dryRun:
				se.println("\n--dry-run: no files were modified. --write would append the printed line(s) to:")
				for _, e := range pending {
					se.printf("  %s\n", e.relPath)
				}
			case write:
				for _, e := range pending {
					if err := enroll.WriteRegistry(repoPath, e.relPath, e.result.NewContent); err != nil {
						return err
					}
					se.printf("\nwrote %s — now commit it: git add .semver-trust && git commit -S\n", e.relPath)
				}
			}

			if so.err != nil {
				return so.err
			}
			return se.err
		},
	}

	f := cmd.Flags()
	f.StringVar(&repoPath, "repo", ".", "repository to enroll into")
	f.StringVar(&email, "email", "", "principal to enroll (default: git user.email)")
	f.StringVar(&commitKey, "commit-key", "", "path to an SSH public key to enroll as a commit signer")
	f.StringVar(&attestKey, "attest-key", "", "path to an SSH public key to enroll as an attestation signer")
	f.StringVar(&policyPath, "policy", ".semver-trust/policy.toml", "policy file path within the repository")
	f.BoolVar(&write, "write", false, "append the line to the working-tree registry (atomic)")
	f.BoolVar(&dryRun, "dry-run", false, "print exactly what --write would do; change nothing")
	return cmd
}

// enrollment pairs a built SSH result with the registry it targets.
type enrollment struct {
	flag    string
	relPath string
	result  *enroll.SSHResult
}

// resolvePrincipal maps --email (or the git identity) to the enrolled principal.
// Defaulting from git user.email makes the registry-principal-equals-commit-identity
// invariant true by construction; an explicit --email is disclosed with a caution.
func resolvePrincipal(email, repo string) (principal, note string, err error) {
	if email != "" {
		return email, "(--email override — ensure it matches your commit identity)", nil
	}
	_, e, terr := vcs.Tagger(repo)
	if terr != nil {
		return "", "", fmt.Errorf("enroll: no --email given and %w", terr)
	}
	return e, "(from git user.email)", nil
}

// loadEnrollPolicy fences and parses the working-tree policy; enroll needs it to map
// each target flag to its policy-named registry path.
func loadEnrollPolicy(repo, policyPath string) (*policy.Policy, error) {
	abs, err := pathfence.Resolve(repo, policyPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("enroll: cannot read policy %s: %w", policyPath, err)
	}
	pol, err := policy.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("enroll: policy does not parse: %w", err)
	}
	return pol, nil
}

// buildSSHTarget loads the public key and builds the enrollment for one SSH target,
// reading the target and cross registries through the fence.
func buildSSHTarget(repo, keyPath, flag, targetRel, targetName, crossRel, namespace, principal string, at time.Time) (enrollment, error) {
	if targetRel == "" {
		return enrollment{}, fmt.Errorf("enroll: policy declares no %s registry (needed for %s)", targetName, flag)
	}
	pub, err := readPubKey(keyPath)
	if err != nil {
		return enrollment{}, fmt.Errorf("%s %q: %w", flag, keyPath, err)
	}
	existing, err := readFencedRegistry(repo, targetRel)
	if err != nil {
		return enrollment{}, err
	}
	var cross []byte
	if crossRel != "" {
		cross, err = readFencedRegistry(repo, crossRel)
		if err != nil {
			return enrollment{}, err
		}
	}
	res, err := enroll.BuildSSH(pub, principal, namespace, existing, cross, at)
	if err != nil {
		return enrollment{}, fmt.Errorf("%s: %w", flag, err)
	}
	return enrollment{flag: flag, relPath: targetRel, result: res}, nil
}

// readPubKey reads and parses an SSH public key file. The key path is the user's own
// (typically under ~/.ssh), not a policy-named repo path, so it is read directly.
func readPubKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("not an SSH public key: %w", err)
	}
	return pub, nil
}

// readFencedRegistry fences and reads a policy-named registry; a not-yet-created
// registry (the parent may still be missing) reads as empty, which BuildSSH handles.
func readFencedRegistry(repo, rel string) ([]byte, error) {
	abs, err := pathfence.Resolve(repo, rel)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return data, nil
}
