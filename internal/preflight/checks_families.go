// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/pathfence"
	"github.com/semver-trust/semver-trust-go/internal/pgp"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/trust"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

// catalogFamilies returns the PR-B checks: the keys, registry, policy, and
// simulate families that wrap verification's own primitives.
func catalogFamilies() []Check {
	all := []Persona{Maintainer, Contributor, Agent}
	mc := []Persona{Maintainer, Contributor}
	m := []Persona{Maintainer}
	return []Check{
		{ID: "keys/signing-key-loads", Personas: mc, Run: checkSigningKeyLoads},
		{ID: "keys/attestation-distinct", Personas: m, Run: checkAttestationDistinct},
		{ID: "registry/principal-enrolled", Personas: mc, Run: checkPrincipalEnrolled},
		{ID: "registry/gpg-keyring", Personas: m, Run: checkGPGKeyring},
		{ID: "registry/bot-accounts", Personas: m, Run: checkBotAccounts},
		{ID: "policy/meta-coverage", Personas: m, Run: checkMetaCoverage},
		{ID: "policy/adoption-boundary", Personas: m, Run: checkAdoptionBoundary},
		{ID: "simulate/classify", Personas: all, Run: checkSimulateClassify},
		{ID: "simulate/commit", Personas: all, Run: checkSimulateCommit},
	}
}

// ---- shared helpers --------------------------------------------------------

// readRegistry fences and reads a policy-named allowed-signers registry from the
// working tree, returning its entries and the fence/read/parse error (so a check
// can fail closed on a declared-but-uncheckable registry). A parsed-but-empty
// registry is (nil, nil).
func readRegistry(env *Env, relPath string) ([]sshsig.AllowedSigner, error) {
	if relPath == "" {
		return nil, nil
	}
	abs, err := pathfence.Resolve(env.Repo, relPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	return sshsig.ParseAllowedSigners(data)
}

// parseRegistry is readRegistry for callers that treat any error as "no
// registry" — they are counterbalanced by registry/parse on allowed_signers.
func parseRegistry(env *Env, relPath string) []sshsig.AllowedSigner {
	signers, _ := readRegistry(env, relPath)
	return signers
}

// enrolledPrincipals is the set of principals in the policy's allowed_signers.
func enrolledPrincipals(env *Env) map[string]bool {
	if env.Policy == nil {
		return nil
	}
	signers := parseRegistry(env, env.Policy.Identity.Human.AllowedSigners)
	if signers == nil {
		return nil
	}
	set := map[string]bool{}
	for _, s := range signers {
		for _, p := range s.Principals {
			set[p] = true
		}
	}
	return set
}

// signingPubkey loads the configured SSH commit-signing public key. It returns
// ok=false when signing is GPG (a key id, not loadable without the keyring), or
// when the configured key does not load — the caller maps that to SKIP/FAIL. The
// signing key path is the user's own git configuration (typically under ~/.ssh),
// NOT a policy-named repo path, so it is read directly rather than fenced.
func signingPubkey(env *Env) (ssh.PublicKey, bool) {
	g := env.Git
	if g == nil || g.GPGFormat != "ssh" || g.SigningKey == "" {
		return nil, false
	}
	var data []byte
	if strings.HasPrefix(g.SigningKey, "ssh-") {
		data = []byte(g.SigningKey)
	} else {
		b, err := os.ReadFile(expandHome(g.SigningKey))
		if err != nil {
			return nil, false
		}
		data = b
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, false
	}
	return pub, true
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
		}
	}
	return path
}

// ---- keys/ -----------------------------------------------------------------

func checkSigningKeyLoads(env *Env) Result {
	g := env.Git
	if g.SigningKey == "" {
		return skip("no user.signingkey configured")
	}
	if g.GPGFormat != "ssh" {
		return skip("gpg.format is not ssh — the GPG signing key is not loadable without its keyring")
	}
	pub, ok := signingPubkey(env)
	if !ok {
		return fail("configured user.signingkey does not load as an SSH public key",
			"§10 step 3 (verify signature)", "point user.signingkey at a readable .pub file")
	}
	return pass("signing key loads: " + ssh.FingerprintSHA256(pub))
}

func checkAttestationDistinct(env *Env) Result {
	if env.Policy == nil || env.Policy.Identity.AttestationSigners == "" {
		return skip("policy declares no attestation_signers")
	}
	pub, ok := signingPubkey(env)
	if !ok {
		return skip("no loadable SSH signing key to compare")
	}
	signers, err := readRegistry(env, env.Policy.Identity.AttestationSigners)
	if err != nil {
		// This is the one check enforcing ADR-040's distinctness; a declared but
		// uncheckable attestation registry must fail closed, not pass.
		return fail("cannot verify two-key distinctness — attestation_signers unreadable: "+err.Error(),
			"§9 (two-key separation)", "fix the attestation_signers registry")
	}
	fp := ssh.FingerprintSHA256(pub)
	for _, s := range signers {
		if s.Key != nil && ssh.FingerprintSHA256(s.Key) == fp {
			return fail("the commit signing key is also enrolled in attestation_signers — commit and attestation keys must be distinct (ADR-022/040)",
				"§9 (two-key separation)", "use a separate attestation key: semver-trust enroll --attest-key <other>.pub")
		}
	}
	return pass("commit signing key is distinct from the attestation keys")
}

// ---- registry/ -------------------------------------------------------------

func checkPrincipalEnrolled(env *Env) Result {
	_, email, err := vcs.Tagger(env.Repo)
	if err != nil || email == "" {
		return skip("no git user.email to check")
	}
	enrolled := enrolledPrincipals(env)
	if enrolled == nil {
		return skip("no allowed_signers registry to check")
	}
	if enrolled[email] {
		return pass(email + " is enrolled in allowed_signers")
	}
	if env.Persona == Contributor {
		return warn(email+" is not yet enrolled in allowed_signers (expected until your enrollment PR merges)",
			"semver-trust enroll --commit-key <key>.pub   # then commit the printed line")
	}
	return fail(email+" is not enrolled in allowed_signers — your commits will not verify",
		"§10 step 3 (verify signature)", "semver-trust enroll --commit-key <key>.pub   # then commit the printed line")
}

func checkGPGKeyring(env *Env) Result {
	if env.Policy == nil {
		return skip("policy does not parse")
	}
	path := env.Policy.Identity.Human.GPGKeyring
	if path == "" {
		return skip("policy declares no [identity.human] gpg_keyring")
	}
	abs, ferr := pathfence.Resolve(env.Repo, path)
	if ferr != nil {
		return fail("gpg_keyring path refused: "+ferr.Error(), "§10 step 3 (verify signature)", "fix the policy's gpg_keyring path")
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return fail("gpg_keyring not readable: "+err.Error(), "§10 step 3 (verify signature)", "add "+path)
	}
	kr, err := pgp.ParseKeyring(data)
	if err != nil {
		return fail("gpg_keyring does not parse: "+err.Error(), "§10 step 3 (verify signature)", "fix "+path)
	}
	if n := len(kr.Principals()); n == 0 {
		return fail("gpg_keyring is declared but empty — a declared-but-empty keyring fails closed",
			"§10 step 3 (verify signature)", "add the GPG public keys, or drop gpg_keyring from the policy")
	}
	return pass(fmt.Sprintf("gpg_keyring: %d key(s)", len(kr.Principals())))
}

func checkBotAccounts(env *Env) Result {
	if env.Policy == nil {
		return skip("policy does not parse")
	}
	bots := env.Policy.Identity.Agent.BotAccounts
	if len(bots) == 0 {
		return skip("policy declares no [identity.agent] bot_accounts")
	}
	enrolled := enrolledPrincipals(env)
	var missing []string
	for _, b := range bots {
		if !enrolled[b] {
			missing = append(missing, b)
		}
	}
	if len(missing) > 0 {
		return warn("bot_accounts not enrolled as signers: "+strings.Join(missing, ", ")+" — platform merges from these classify unknown-signer",
			"enroll the bot account(s) in allowed_signers")
	}
	return pass(fmt.Sprintf("%d bot account(s) enrolled", len(bots)))
}

// ---- policy/ ---------------------------------------------------------------

func checkMetaCoverage(env *Env) Result {
	if env.Policy == nil {
		return skip("policy does not parse")
	}
	meta := env.Policy.Meta.Paths
	if len(meta) == 0 {
		return skip("policy declares no meta paths")
	}
	required := []string{env.PolicyPath, ".github/workflows/ci.yml"}
	if p := env.Policy.Identity.Human.AllowedSigners; p != "" {
		required = append(required, p)
	}
	if p := env.Policy.Identity.Human.GPGKeyring; p != "" {
		required = append(required, p)
	}
	if p := env.Policy.Identity.AttestationSigners; p != "" {
		required = append(required, p)
	}
	var uncovered []string
	for _, p := range required {
		covered, err := trust.MetaPathCovers(meta, p)
		if err != nil {
			return fail("meta-path glob error: "+err.Error(), "§10 step 1 (load policy)", "fix [meta] paths")
		}
		if !covered {
			uncovered = append(uncovered, p)
		}
	}
	if len(uncovered) > 0 {
		return warn("meta-paths do not cover: "+strings.Join(uncovered, ", ")+" — a below-required change to these would not hard-abort (§5.4)",
			"add the path(s) to [meta] paths")
	}
	return pass("meta-paths cover the policy, registries, and CI workflows")
}

func checkAdoptionBoundary(env *Env) Result {
	if env.Policy == nil {
		return skip("policy does not parse")
	}
	b := env.Policy.AdoptionBoundary
	if b == "" {
		return skip("no adoption boundary declared")
	}
	if _, err := vcs.ResolveCommit(env.Repo, b); err != nil {
		return fail("adoption_boundary "+b+" does not resolve: "+err.Error(),
			"§10 step 2 (enumerate commits)", "point adoption_boundary at an existing revision")
	}
	return pass("adoption_boundary " + b + " resolves; its authority is the out-of-band descriptor (ADR-027/028) — descriptor-match not checkable without --bootstrap-descriptor")
}

// ---- simulate/ -------------------------------------------------------------

func checkSimulateClassify(env *Env) Result {
	if len(env.Message) == 0 {
		return skip("no --message to classify")
	}
	msg := string(env.Message)
	prov := vcs.ParseTrailers(msg).Provenance()
	required := env.Policy != nil && env.Policy.TrailersRequired
	if prov == "" {
		// The killer detection: a message that contains "Provenance:" but not as
		// the final trailer paragraph parses as absent and floors T0 (§4.1).
		if strings.Contains(msg, "Provenance:") {
			return fail(`the message contains "Provenance:" but it is not the final trailer paragraph — it parses as absent and floors the scope at T0`,
				"§10 step 3 (classify)", "move the Provenance trailer to the final paragraph")
		}
		if required {
			return fail("no Provenance trailer, and the policy requires one — the commit classifies ambiguous and floors T0",
				"§10 step 3 (classify)", `add a final "Provenance: human|agent|mixed" paragraph`)
		}
		return warn("no Provenance trailer", `add a final "Provenance: …" paragraph`)
	}
	switch prov {
	case "human", "agent", "mixed":
		return pass("Provenance: " + prov)
	default:
		return fail("invalid Provenance value "+prov, "§10 step 3 (classify)", "use human|agent|mixed")
	}
}

func checkSimulateCommit(env *Env) Result {
	if env.Commit == "" {
		return skip("no --commit to verify")
	}
	if env.Policy == nil {
		return skip("policy does not parse — cannot classify a commit")
	}
	sha, err := vcs.ResolveCommit(env.Repo, env.Commit)
	if err != nil {
		return fail("cannot resolve --commit "+env.Commit+": "+err.Error(), "§10 step 2 (enumerate commits)", "check the revision")
	}
	trusted, av, err := verify.LoadTrustMaterial(verify.Options{RepoPath: env.Repo, To: sha, PolicyPath: env.PolicyPath}, env.Policy, env.Repo)
	if err != nil {
		return fail("cannot load trust material: "+err.Error(), "§10 step 1 (load policy)", "semver-trust policy validate")
	}
	commits, err := vcs.Range(env.Repo, "", sha)
	if err != nil {
		return fail("cannot enumerate to "+sha[:12]+": "+err.Error(), "§10 step 2 (enumerate commits)", "check the revision")
	}
	var target vcs.RangeCommit
	for _, c := range commits {
		if c.Hash == sha {
			target = c
			break
		}
	}
	if target.Hash == "" {
		return fail("commit "+sha[:12]+" not found in history", "§10 step 2 (enumerate commits)", "check the revision")
	}
	row, _, err := verify.ClassifyCommit(env.Repo, target, trusted, av, env.Policy, env.At)
	if err != nil {
		var ab *verify.AbortError
		if errors.As(err, &ab) {
			return fail("commit "+sha[:12]+" would abort verification: "+err.Error(), ab.Step, "fix the commit's signature or review before release")
		}
		return fail("classify error: "+err.Error(), "§10 step 3 (classify)", "")
	}
	return pass(fmt.Sprintf("commit %s classifies %s (%s / review %s)", row.Short, row.Level, row.Authorship, row.Review))
}
