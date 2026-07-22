// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"bytes"
	"fmt"
	"os"

	"github.com/semver-trust/semver-trust-go/internal/gitconfig"
	"github.com/semver-trust/semver-trust-go/internal/pathfence"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

// Catalog is the full doctor check catalog: the config family plus policy/parse
// and registry/parse (the foundation), then the keys/registry/policy/simulate
// trust-material families (catalogFamilies), then the softer chain/history/trust/
// remote-platform tier (catalogSoftTier).
func Catalog() []Check {
	all := []Persona{Maintainer, Contributor, Agent}
	mc := []Persona{Maintainer, Contributor}
	c := []Persona{Contributor}
	checks := []Check{
		{ID: "config/git-binary", Personas: all, Run: checkGitBinary},
		{ID: "config/identity", Personas: mc, Run: checkConfigIdentity},
		{ID: "config/signing-enabled", Personas: all, Run: checkSigningEnabled},
		{ID: "config/commit-template", Personas: c, Run: checkCommitTemplate},
		{ID: "config/allowed-signers-file", Personas: c, Run: checkAllowedSignersFile},
		{ID: "config/hook", Personas: c, Run: checkHook},
		{ID: "policy/parse", Personas: all, Run: checkPolicyParse},
		{ID: "registry/parse", Personas: mc, Run: checkRegistryParse},
	}
	checks = append(checks, catalogFamilies()...)
	return append(checks, catalogSoftTier()...)
}

// includeCaveat discloses that a config-derived answer may live in an included
// file go-git cannot see (SU-5); the git binary read it correctly, but the human
// should know the value's provenance.
func includeCaveat(g *gitconfig.Config) string {
	if g != nil && g.HasIncludes {
		return " (include/includeIf present; value may come from an included file)"
	}
	return ""
}

// checkGitBinary reports the resolved git executable every environment command
// (doctor's own reads, and setup's writes) shells out to. Surfacing the absolute
// path makes PATH hijack — the residual risk of shelling out (ADR-042) — visible: a
// planted `git` earlier on PATH is checkable here rather than silent.
func checkGitBinary(env *Env) Result {
	if env.Git == nil || env.Git.GitPath == "" {
		return skip("git binary not resolved")
	}
	return pass("git binary: " + env.Git.GitPath + includeCaveat(env.Git))
}

func checkConfigIdentity(env *Env) Result {
	g := env.Git
	if g.Bare {
		return skip("bare repository — no working-tree identity to configure")
	}
	if g.UserName == "" || g.UserEmail == "" {
		return fail("git user.name / user.email not set",
			"§10 step 3 (verify signature)",
			`git config user.name "Alex Doe" && git config user.email alex@example.com`)
	}
	return pass(fmt.Sprintf("%s <%s>%s", g.UserName, g.UserEmail, includeCaveat(g)))
}

func checkSigningEnabled(env *Env) Result {
	g := env.Git
	if g.Bare {
		return skip("bare repository — signing is configured per work tree")
	}
	if g.SigningKey == "" || g.CommitGPGSign != "true" {
		return fail("commit signing not enabled (user.signingkey / commit.gpgsign) — unsigned commits abort verification",
			"§10 step 3 (verify signature)",
			"semver-trust setup --signing-key ~/.ssh/semver-trust-commit.pub")
	}
	note := ""
	if g.GPGFormat == "" {
		note = " (gpg.format unset → OpenPGP)"
	}
	return pass("commit signing enabled" + note + includeCaveat(g))
}

func checkCommitTemplate(env *Env) Result {
	if env.Git.CommitTemplate == "" {
		return warn("commit.template not set — a non-interactive `git commit -m` ships no Provenance trailer",
			`printf 'Provenance: human\n' > .gitmessage && git config commit.template .gitmessage`)
	}
	return pass("commit.template " + env.Git.CommitTemplate)
}

func checkAllowedSignersFile(env *Env) Result {
	if env.Git.AllowedSignersFile == "" {
		return warn("gpg.ssh.allowedSignersFile not set — local `git log --format=%G?` cannot verify",
			"git config gpg.ssh.allowedSignersFile .semver-trust/allowed_signers")
	}
	return pass("allowed-signers file " + env.Git.AllowedSignersFile)
}

func checkHook(env *Env) Result {
	if env.Git.HooksPath == "" {
		return warn("core.hooksPath not set — the commit-msg trailer hook is not installed",
			"git config core.hooksPath .githooks")
	}
	return pass("hooksPath " + env.Git.HooksPath)
}

func checkPolicyParse(env *Env) Result {
	if env.PolicyErr != nil {
		return fail("policy could not be loaded ("+env.PolicyErr.Error()+") — the config is the root of trust",
			"§10 step 1 (load policy)", "semver-trust policy validate")
	}
	if env.Policy == nil {
		return fail("no policy at "+env.PolicyPath,
			"§10 step 1 (load policy)", "add "+env.PolicyPath)
	}
	head, present, err := verify.ReadTreeFileIfPresent(env.Repo, "HEAD", env.PolicyPath)
	if err != nil {
		// Not the fresh-repo case: the repository would not open, or an object
		// was unreadable/corrupt. The comparison could not run, so say so with the
		// error rather than falsely asserting either "matches HEAD" or "not yet
		// committed".
		return warn("policy parses, but its HEAD comparison could not run: "+err.Error(),
			"inspect the repository/object error above, then re-run doctor")
	}
	if !present {
		// No committed policy to compare against yet — a fresh repo with no
		// commits, or a policy not yet in HEAD's tree. Parsing succeeded, but no
		// drift check ran, so do not claim it matches HEAD.
		return pass("policy parses (not yet committed — no HEAD version to compare against)")
	}
	if !bytes.Equal(head, env.PolicyRaw) {
		return warn("working-tree policy differs from HEAD — verify reads the range tip's tree, not your checkout",
			"commit the policy change before relying on it")
	}
	return pass("policy parses; matches HEAD")
}

func checkRegistryParse(env *Env) Result {
	if env.Policy == nil {
		return skip("policy does not parse — registries not resolvable")
	}
	path := env.Policy.Identity.Human.AllowedSigners
	if path == "" {
		return skip("policy declares no [identity.human] allowed_signers")
	}
	abs, err := pathfence.Resolve(env.Repo, path)
	if err != nil {
		return fail("allowed_signers path refused: "+err.Error(),
			"§10 step 3 (verify signature)", "fix the policy's allowed_signers path")
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return fail("allowed_signers not readable: "+err.Error(),
			"§10 step 3 (verify signature)", "add "+path)
	}
	if _, err := sshsig.ParseAllowedSigners(data); err != nil {
		return fail("allowed_signers does not parse: "+err.Error(),
			"§10 step 3 (verify signature)", "fix "+path)
	}
	head, present, err := verify.ReadTreeFileIfPresent(env.Repo, "HEAD", path)
	if err != nil {
		// Not the fresh-repo case: the repository would not open, or an object was
		// unreadable/corrupt. Surface it rather than claim a comparison happened.
		return warn("allowed_signers parses, but its HEAD comparison could not run: "+err.Error(),
			"inspect the repository/object error above, then re-run doctor")
	}
	if !present {
		// No committed registry to compare against yet (no commits, or not yet in
		// HEAD's tree). Parsing succeeded; no drift check ran.
		return pass("allowed_signers parses (not yet committed — no HEAD version to compare against)")
	}
	if !bytes.Equal(head, data) {
		return warn("working-tree allowed_signers differs from HEAD — verify reads the tip's tree",
			"commit the registry change")
	}
	return pass("allowed_signers parses; matches HEAD")
}
