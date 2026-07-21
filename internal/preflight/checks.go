// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"bytes"
	"fmt"
	"os"

	"github.com/semver-trust/semver-trust-go/internal/pathfence"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

// Catalog is the full doctor check catalog: the config family plus policy/parse
// and registry/parse (the foundation), then the keys/registry/policy/simulate
// families (catalogFamilies). The chain/history/trust/remote tier lands in a
// following PR.
func Catalog() []Check {
	all := []Persona{Maintainer, Contributor, Agent}
	mc := []Persona{Maintainer, Contributor}
	c := []Persona{Contributor}
	checks := []Check{
		{ID: "config/identity", Personas: mc, Run: checkConfigIdentity},
		{ID: "config/signing-enabled", Personas: all, Run: checkSigningEnabled},
		{ID: "config/commit-template", Personas: c, Run: checkCommitTemplate},
		{ID: "config/allowed-signers-file", Personas: c, Run: checkAllowedSignersFile},
		{ID: "config/hook", Personas: c, Run: checkHook},
		{ID: "policy/parse", Personas: all, Run: checkPolicyParse},
		{ID: "registry/parse", Personas: mc, Run: checkRegistryParse},
	}
	return append(checks, catalogFamilies()...)
}

// includeCaveat discloses that a config-derived answer may live in an included
// file go-git cannot see (SU-5); the git binary read it correctly, but the human
// should know the value's provenance.
func includeCaveat(g *GitConfig) string {
	if g != nil && g.HasIncludes {
		return " (include/includeIf present; value may come from an included file)"
	}
	return ""
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
	if head, err := verify.ReadTreeFile(env.Repo, "HEAD", env.PolicyPath); err == nil && !bytes.Equal(head, env.PolicyRaw) {
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
	if head, err := verify.ReadTreeFile(env.Repo, "HEAD", path); err == nil && !bytes.Equal(head, data) {
		return warn("working-tree allowed_signers differs from HEAD — verify reads the tip's tree",
			"commit the registry change")
	}
	return pass("allowed_signers parses; matches HEAD")
}
