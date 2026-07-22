// SPDX-License-Identifier: Apache-2.0

// Package gitconfig is the bootstrap family's git-binary environment layer: it reads
// and writes a clone's git configuration through the user's `git` binary, never
// go-git (ADR-042). git provides config.lock locking, include/includeIf semantics,
// linked-worktree config routing, and GIT_DIR handling for free, where the pinned
// go-git config writer is a lockless, comment-destroying, truncate-in-place rewrite.
// It is shared by `doctor` (read-only diagnosis) and `setup` (the config writer).
// Verification never uses this package — it stays pure go-git for determinism.
package gitconfig

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Config is this clone's git configuration and environment facts, read through the
// git binary (ADR-042): git handles config.lock, include/includeIf, linked-worktree
// config routing, and GIT_DIR correctly, where go-git resolves an EMPTY config inside
// a linked worktree — which would make a naive doctor report everything unconfigured.
type Config struct {
	// GitPath is the resolved git executable. Surfacing it makes PATH hijack — the
	// residual risk of shelling out — visible (the setup/PATH-hijack note): a planted
	// `git` earlier on PATH is checkable rather than silent.
	GitPath string `json:"git_path"`

	UserName           string `json:"user_name,omitempty"`
	UserEmail          string `json:"user_email,omitempty"`
	GPGFormat          string `json:"gpg_format,omitempty"`
	SigningKey         string `json:"signing_key,omitempty"`
	CommitGPGSign      string `json:"commit_gpgsign,omitempty"`
	CommitTemplate     string `json:"commit_template,omitempty"`
	AllowedSignersFile string `json:"allowed_signers_file,omitempty"`
	HooksPath          string `json:"hooks_path,omitempty"`

	InsideWorkTree bool   `json:"inside_work_tree"`
	Bare           bool   `json:"bare"`
	GitDir         string `json:"git_dir,omitempty"`
	TopLevel       string `json:"top_level,omitempty"`

	// FetchRefspecs is remote.origin.fetch (all values) — checked for the
	// attestation refspec (ADR-043).
	FetchRefspecs []string `json:"fetch_refspecs,omitempty"`

	// HasIncludes reports include/includeIf directives; when set, config-derived
	// answers carry a disclosed caveat (go-git does not expand includes, and a
	// managed key may live in an included file).
	HasIncludes bool `json:"has_includes"`
}

// Load reads the clone at repo through the git binary.
func Load(repo string) (*Config, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("gitconfig: git not found on PATH: %w", err)
	}
	g := &Config{GitPath: gitPath}

	run := func(args ...string) (string, bool) {
		cmd := exec.Command(gitPath, append([]string{"-C", repo}, args...)...) //nolint:gosec // gitPath is resolved from PATH; args are constants
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err != nil {
			return "", false // unset key or error → treated as not present
		}
		return strings.TrimSpace(out.String()), true
	}
	get := func(key string) string { v, _ := run("config", "--get", key); return v }

	g.UserName = get("user.name")
	g.UserEmail = get("user.email")
	g.GPGFormat = get("gpg.format")
	g.SigningKey = get("user.signingkey")
	g.CommitGPGSign = get("commit.gpgsign")
	g.CommitTemplate = get("commit.template")
	g.AllowedSignersFile = get("gpg.ssh.allowedsignersfile")
	g.HooksPath = get("core.hookspath")

	if v, ok := run("rev-parse", "--is-inside-work-tree"); ok {
		g.InsideWorkTree = v == "true"
	}
	if v, ok := run("rev-parse", "--is-bare-repository"); ok {
		g.Bare = v == "true"
	}
	if v, ok := run("rev-parse", "--git-dir"); ok {
		g.GitDir = v
	}
	if v, ok := run("rev-parse", "--show-toplevel"); ok {
		g.TopLevel = v
	}
	if _, ok := run("config", "--get-regexp", "include"); ok {
		g.HasIncludes = true
	}
	if out, ok := run("config", "--get-all", "remote.origin.fetch"); ok && out != "" {
		g.FetchRefspecs = strings.Split(out, "\n")
	}
	return g, nil
}

// Git is a resolved git binary bound to a repository — the WRITER used by setup. It
// carries the SAME resolved Path a prior Load produced, so read and write use one git
// executable (a single PATH-hijack surface). Unlike Load's reader, its run surfaces
// stderr in the error: a write failure must not be swallowed.
type Git struct {
	Path string // the resolved git executable (Config.GitPath)
	Repo string
}

// run executes `git -C repo <args...>` and returns trimmed stdout, or an error that
// includes git's stderr AND wraps the underlying exec error (%w) so a caller can
// inspect the exit status via isUnsetKey — a genuinely-unset key must be
// distinguishable from a real failure (broken config, invalid repo, exec error).
func (g Git) run(args ...string) (string, error) {
	cmd := exec.Command(g.Path, append([]string{"-C", g.Repo}, args...)...) //nolint:gosec // Path is a resolved git binary; args are command-controlled keys/values
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(errBuf.String()); msg != "" {
			return "", fmt.Errorf("git %s: %s: %w", strings.Join(args, " "), msg, err)
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(out.String()), nil
}

// isUnsetKey reports whether err is git config's expected "key not present" status —
// exit code 1 from `git config --get`/`--get-all` — as opposed to a real failure
// (invalid config = 3, not-a-repository = 128, an exec error, …). Only this status
// may be normalized to "absent"; every other error must surface.
func isUnsetKey(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 1
}

// GetLocal reads a repo-LOCAL config value (git config --local --get <key>) — the
// scope setup writes, and therefore the scope its conflict detection compares
// against: a value inherited from global or an include is OVERRIDDEN by a local
// write, not clobbered, so it is not a conflict. A genuinely-unset local key is
// ("", nil); a real failure (invalid config, exec error) surfaces.
func (g Git) GetLocal(key string) (string, error) {
	out, err := g.run("config", "--local", "--get", key)
	if err != nil {
		if isUnsetKey(err) {
			return "", nil
		}
		return "", err
	}
	return out, nil
}

// Set writes a single repo-local config key (git config <key> <value>), under git's
// own config.lock protocol.
func (g Git) Set(key, value string) error {
	_, err := g.run("config", key, value)
	return err
}

// Unset removes a repo-local config key (git config --unset <key>) — the reversal of
// Set, used to build the reversal receipt.
func (g Git) Unset(key string) error {
	_, err := g.run("config", "--unset", key)
	return err
}

// AddFetch appends a fetch refspec to a remote (git config --add
// remote.<remote>.fetch <refspec>) — additive, never overwriting existing refspecs.
func (g Git) AddFetch(remote, refspec string) error {
	_, err := g.run("config", "--add", "remote."+remote+".fetch", refspec)
	return err
}

// FetchRefspecs returns a remote's configured fetch refspecs (git config --get-all).
// A genuinely-unset key is (nil, nil): no refspecs, not an error. Any OTHER failure
// (broken config, invalid repo, exec error) is returned — the planner must not
// mistake a broken state for "no refspecs" and then write from it.
func (g Git) FetchRefspecs(remote string) ([]string, error) {
	out, err := g.run("config", "--get-all", "remote."+remote+".fetch")
	if err != nil {
		if isUnsetKey(err) {
			return nil, nil
		}
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

// RemoteURL returns a remote's URL (git config --get remote.<remote>.url), or "" when
// the remote is genuinely not configured — surfaced in setup's remote echo (SU-8).
// A non-"unset" failure is returned rather than masked as an absent remote.
func (g Git) RemoteURL(remote string) (string, error) {
	out, err := g.run("config", "--get", "remote."+remote+".url")
	if err != nil {
		if isUnsetKey(err) {
			return "", nil
		}
		return "", err
	}
	return out, nil
}
