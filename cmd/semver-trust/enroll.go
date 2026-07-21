// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
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
		gpgPubkey  string
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

A --commit-key / --attest-key is an SSH public key; its principal defaults from git
user.email (the same identity your commits carry), so the registry principal equals
your commit identity by construction. Namespaces come from compiled constants, so
the "git" / attestation namespace can never be mistyped. --gpg-pubkey enrolls an
armored OpenPGP public key you exported yourself (gpg --armor --export <keyid>);
the tool never shells out to gpg, never takes a bare key id, and refuses private-key
material. Export to a file and inspect it before enrolling — a one-line
network-to-trust-root pipe is exactly the ceremony this command exists to slow down.

--write appends to the working-tree registry named by the policy, under the atomic
writer contract (ADR-039): a repo-relative path fence, no directory creation, a
strict re-parse of the whole result, and a temp-file + fsync + rename. --dry-run
makes zero filesystem changes and prints exactly what --write would do.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The clock is read once here at the process boundary (ADR-018); it feeds
			// the enrollment self-check's validity window.
			at := time.Now()

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
			if gpgPubkey != "" {
				targets++
			}
			if targets == 0 {
				return errors.New("enroll: at least one of --commit-key, --attest-key, or --gpg-pubkey is required")
			}

			// The principal (an SSH allowed-signers identity) is needed only for the
			// SSH targets; a GPG key carries its own user-ID, so a --gpg-pubkey-only
			// enroll never consults git user.email.
			var principal, principalNote string
			if commitKey != "" || attestKey != "" {
				if principal, principalNote, err = resolvePrincipal(email, repoPath); err != nil {
					return err
				}
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

			var gpgPending *gpgEnrollment
			if gpgPubkey != "" {
				g, err := buildGPGTarget(cmd, repoPath, gpgPubkey, pol.Identity.Human.GPGKeyring)
				if err != nil {
					return err
				}
				gpgPending = g
			}

			so := &errWriter{w: cmd.OutOrStdout()}
			se := &errWriter{w: cmd.ErrOrStderr()}

			// Print-by-default: ONLY the byte-exact material on stdout (safe for `>>`).
			for _, e := range pending {
				so.println(e.result.Line)
			}
			if gpgPending != nil {
				so.printf("%s", gpgPending.candidate)
			}

			// All guidance, disclosure, and warnings on stderr.
			if len(pending) > 0 {
				se.printf("\nprincipal: %s %s\n", principal, principalNote)
			}
			for _, e := range pending {
				se.printf("%s → %s  (fingerprint %s)\n", e.flag, e.relPath, e.result.Fingerprint)
				if e.result.Warn != "" {
					se.printf("  warn: %s\n", e.result.Warn)
				}
			}
			if gpgPending != nil {
				se.printf("\n--gpg-pubkey → %s\n", gpgPending.relPath)
				// Always name the candidate key's identity (whose authority is being
				// added), even on a same-email key rotation where the new-principal
				// delta is empty.
				se.printf("  key(s) for:          %s\n", strings.Join(gpgPending.result.CandidatePrincipals, ", "))
				se.printf("  new fingerprint(s):  %s\n", strings.Join(gpgPending.result.NewFingerprints, ", "))
				if len(gpgPending.result.NewPrincipals) > 0 {
					se.printf("  new principal(s):    %s\n", strings.Join(gpgPending.result.NewPrincipals, ", "))
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
				se.println("\n--dry-run: no files were modified. --write would append the printed material to:")
				for _, e := range pending {
					se.printf("  %s\n", e.relPath)
				}
				if gpgPending != nil {
					se.printf("  %s\n", gpgPending.relPath)
				}
			case write:
				for _, e := range pending {
					if err := enroll.WriteRegistry(repoPath, e.relPath, e.result.NewContent); err != nil {
						return err
					}
					se.printf("\nwrote %s — now commit it: git add .semver-trust && git commit -S\n", e.relPath)
				}
				if gpgPending != nil {
					if err := enroll.WriteRegistry(repoPath, gpgPending.relPath, gpgPending.result.NewContent); err != nil {
						return err
					}
					se.printf("\nwrote %s — now commit it: git add .semver-trust && git commit -S\n", gpgPending.relPath)
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
	f.StringVar(&gpgPubkey, "gpg-pubkey", "", "path to an armored OpenPGP public key to enroll (- for stdin)")
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

// gpgEnrollment pairs a built GPG keyring result with the keyring it targets and the
// raw candidate bytes — the validated material printed for `>>` redirection.
type gpgEnrollment struct {
	relPath   string
	candidate []byte
	result    *enroll.GPGResult
}

// buildGPGTarget reads the armored candidate (a file, or "-" for stdin) and builds
// the GPG keyring enrollment against the policy-named gpg_keyring.
func buildGPGTarget(cmd *cobra.Command, repo, src, targetRel string) (*gpgEnrollment, error) {
	if targetRel == "" {
		return nil, errors.New("enroll: policy declares no [identity.human] gpg_keyring registry (needed for --gpg-pubkey)")
	}
	candidate, err := readKeyInput(cmd, src)
	if err != nil {
		return nil, fmt.Errorf("--gpg-pubkey %q: %w", src, err)
	}
	existing, err := readFencedRegistry(repo, targetRel)
	if err != nil {
		return nil, err
	}
	res, err := enroll.BuildGPG(candidate, existing)
	if err != nil {
		return nil, fmt.Errorf("--gpg-pubkey: %w", err)
	}
	return &gpgEnrollment{relPath: targetRel, candidate: candidate, result: res}, nil
}

// readKeyInput reads armored key bytes from a file, or from stdin when src is "-".
// The key material is the user's own (an exported public key), not a policy-named
// repo path, so it is read directly.
func readKeyInput(cmd *cobra.Command, src string) ([]byte, error) {
	if src == "-" {
		return io.ReadAll(cmd.InOrStdin())
	}
	return os.ReadFile(src)
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
