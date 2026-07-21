// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// GitConfig is this clone's git configuration and environment facts, read through
// the git binary (ADR-042): git handles config.lock, include/includeIf, linked-
// worktree config routing, and GIT_DIR correctly, where go-git resolves an EMPTY
// config inside a linked worktree — which would make a naive doctor report
// everything unconfigured.
type GitConfig struct {
	// GitPath is the resolved git executable. Surfacing it makes PATH hijack —
	// the residual risk of shelling out — visible (the M4 setup note).
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

// LoadGitConfig reads the clone at repo through the git binary.
func LoadGitConfig(repo string) (*GitConfig, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("preflight: git not found on PATH: %w", err)
	}
	g := &GitConfig{GitPath: gitPath}

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
