// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/chain"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
	"github.com/semver-trust/semver-trust-go/internal/trust"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

// catalogSoftTier returns the PR-C checks: the softer, mostly-advisory tier —
// keys/simulate hardening plus the chain, history, trust, and remote-platform
// families. These lean WARN/SKIP: they surface latent hazards (an agent about to
// touch trust material, a missing attestation refspec) rather than the hard aborts
// the foundation and trust-material families preempt.
func catalogSoftTier() []Check {
	all := []Persona{Maintainer, Contributor, Agent}
	mc := []Persona{Maintainer, Contributor}
	m := []Persona{Maintainer}
	return []Check{
		{ID: "keys/configured-vs-enrolled", Personas: mc, Run: checkConfiguredVsEnrolled},
		{ID: "keys/sign-roundtrip", Personas: mc, Run: checkSignRoundtrip},
		{ID: "simulate/meta-touch", Personas: all, Run: checkMetaTouch},
		{ID: "simulate/staged-purity", Personas: mc, Run: checkStagedPurity},
		{ID: "simulate/enrollment-line", Personas: mc, Run: checkEnrollmentLine},
		{ID: "trust/agent-provenance", Personas: m, Run: checkAgentProvenance},
		{ID: "history/pre-adoption", Personas: mc, Run: checkPreAdoption},
		{ID: "chain/chain-head", Personas: m, Run: checkChainHead},
		{ID: "remote/fetch-refspec", Personas: mc, Run: checkFetchRefspec},
		{ID: "remote/rulesets", Personas: m, Run: checkRulesets},
		{ID: "remote/release-baseline", Personas: m, Run: checkReleaseBaseline},
	}
}

// stagedPaths lists the paths staged in the index (git diff --cached), read
// through the resolved git binary (ADR-042) — the same reader GitConfig uses.
func stagedPaths(env *Env) ([]string, error) {
	git := "git"
	if env.Git != nil && env.Git.GitPath != "" {
		git = env.Git.GitPath
	}
	cmd := exec.Command(git, "-C", env.Repo, "diff", "--cached", "--name-only") //nolint:gosec // git is resolved from PATH; args are constants
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line != "" {
			paths = append(paths, line)
		}
	}
	return paths, nil
}

// ---- keys/ -----------------------------------------------------------------

func checkConfiguredVsEnrolled(env *Env) Result {
	pub, ok := signingPubkey(env)
	if !ok {
		return skip("no loadable SSH signing key to compare against the registry")
	}
	if env.Policy == nil {
		return skip("policy does not parse — allowed_signers not resolvable")
	}
	signers, err := readRegistry(env, env.Policy.Identity.Human.AllowedSigners)
	if err != nil {
		return skip("allowed_signers not readable (see registry/parse)")
	}
	_, email, _ := vcs.Tagger(env.Repo)
	fp := ssh.FingerprintSHA256(pub)
	for _, s := range signers {
		if s.Key == nil || ssh.FingerprintSHA256(s.Key) != fp {
			continue
		}
		// The configured key IS enrolled. Confirm it is enrolled under this
		// clone's own email — a key enrolled for a different principal is the
		// two-keys-one-human confusion that classifies your commits unknown-signer.
		for _, p := range s.Principals {
			if p == email {
				return pass("configured signing key is enrolled for " + email)
			}
		}
		return warn("configured signing key is enrolled, but not for "+email+" — commits from this clone will classify unknown-signer",
			"enroll this key under "+email+", or set git user.email to the enrolled principal")
	}
	if env.Persona == Contributor {
		return warn("configured signing key is not enrolled in allowed_signers (expected until your enrollment PR merges)",
			"semver-trust enroll --commit-key <key>.pub   # then commit the printed line")
	}
	return fail("configured signing key is not enrolled in allowed_signers — your commits will classify unknown-signer",
		"§10 step 3 (verify signature)", "semver-trust enroll --commit-key <key>.pub   # then commit the printed line")
}

func checkSignRoundtrip(env *Env) Result {
	g := env.Git
	if g == nil || g.GPGFormat != "ssh" || g.SigningKey == "" {
		return skip("no SSH signing key configured for a sign round-trip")
	}
	if strings.HasPrefix(g.SigningKey, "ssh-") {
		return skip("user.signingkey is an inline public key — the private half is not locatable for a round-trip")
	}
	privPath := strings.TrimSuffix(expandHome(g.SigningKey), ".pub")
	pemBytes, err := os.ReadFile(privPath)
	if err != nil {
		return skip("private key not found at " + privPath + " — agent-held, on a hardware token, or elsewhere; round-trip not run")
	}
	signer, err := sshsig.LoadSigner(pemBytes)
	if err != nil {
		return skip("signing key is passphrase-protected or unsupported — round-trip not run (" + err.Error() + ")")
	}
	// DR-2: sign a compiled-in constant, never repository bytes — doctor must not
	// mint a signature over anything an attacker could later present as authentic.
	const probe = "semver-trust doctor sign-roundtrip probe"
	armored, err := sshsig.Sign(signer, vcs.GitSSHNamespace, []byte(probe))
	if err != nil {
		return fail("the signing key failed to sign a constant: "+err.Error(),
			"§10 step 3 (verify signature)", "check the key with: ssh-keygen -Y sign")
	}
	sig, err := sshsig.Parse(armored)
	if err != nil {
		return fail("the produced signature did not parse: "+err.Error(),
			"§10 step 3 (verify signature)", "")
	}
	if err := sig.Verify([]byte(probe)); err != nil {
		return fail("the signing key's own signature did not verify: "+err.Error(),
			"§10 step 3 (verify signature)", "")
	}
	return pass("signing key round-trips (signs + verifies a compiled-in constant)")
}

// ---- simulate/ -------------------------------------------------------------

func checkMetaTouch(env *Env) Result {
	if !env.Staged {
		return skip("no --staged changes to inspect")
	}
	if env.Policy == nil {
		return skip("policy does not parse — meta-paths not resolvable")
	}
	meta := env.Policy.Meta.Paths
	if len(meta) == 0 {
		return skip("policy declares no meta paths")
	}
	paths, err := stagedPaths(env)
	if err != nil {
		return skip("cannot read staged paths: " + err.Error())
	}
	var touched []string
	for _, p := range paths {
		if covered, cerr := trust.MetaPathCovers(meta, p); cerr == nil && covered {
			touched = append(touched, p)
		}
	}
	if len(touched) == 0 {
		return pass("staged changes touch no meta-paths")
	}
	list := strings.Join(touched, ", ")
	if env.Persona == Agent {
		// The agent guardrail (ADR-037): trust material is human territory. An
		// agent staging a meta-path change must stop and surface, not commit.
		return fail("staged changes touch trust material: "+list+" — an agent must not author meta-path changes; stop and surface to your operator",
			"§5.4 (meta-path gate)", "unstage the trust-material change and have a human author it")
	}
	return warn("staged changes touch meta-paths: "+list+" — this commit must individually reach the meta required level ("+env.Policy.Meta.RequiredLevel.String()+")",
		"ensure the commit is human-reviewed to reach the required level")
}

func checkStagedPurity(env *Env) Result {
	if !env.Staged {
		return skip("no --staged changes to inspect")
	}
	if env.Policy == nil {
		return skip("policy does not parse — meta-paths not resolvable")
	}
	meta := env.Policy.Meta.Paths
	if len(meta) == 0 {
		return skip("policy declares no meta paths")
	}
	paths, err := stagedPaths(env)
	if err != nil {
		return skip("cannot read staged paths: " + err.Error())
	}
	if len(paths) == 0 {
		return skip("nothing staged")
	}
	var hasMeta, hasOther bool
	for _, p := range paths {
		if covered, cerr := trust.MetaPathCovers(meta, p); cerr == nil && covered {
			hasMeta = true
		} else {
			hasOther = true
		}
	}
	if hasMeta && hasOther {
		return warn("staged changes mix trust material and ordinary code — a mixed adoption/enrollment commit is harder to review to the meta required level",
			"stage the trust-material change as its own commit")
	}
	return pass("staged changes are pure (all meta, or all ordinary)")
}

func checkEnrollmentLine(env *Env) Result {
	if len(env.EnrollmentLine) == 0 {
		return skip("no --enrollment-line to check")
	}
	// Dry-run a candidate registry line through the verifier's own strict parser
	// before the enrollment PR exists. A malformed line — the classic problem #2,
	// an unquoted namespaces=git that the parser reads as the wrong field — is caught
	// here, in front of the human, not at a later verify abort.
	signers, err := sshsig.ParseAllowedSigners(env.EnrollmentLine)
	if err != nil {
		return fail("candidate enrollment line does not parse: "+err.Error(),
			"§10 step 3 (verify signature)", `check the format — the namespace must be quoted: namespaces="git"`)
	}
	if len(signers) == 0 {
		return skip("no enrollment line found (only blanks/comments)")
	}
	// Each candidate must declare its namespace(s) explicitly and resolve in each,
	// at the diagnosis instant, via the same resolver verification uses. An OMITTED
	// namespace is a FAIL, not a default: sshsig treats an empty namespace list as
	// matching EVERY namespace, so an unscoped line would trust the key for both
	// commit signing and attestation — a broader authority than enroll ever emits.
	for _, s := range signers {
		if len(s.Namespaces) == 0 {
			return fail("candidate line omits namespaces=, so the key would be trusted in EVERY namespace (commit AND attestation) — enrollment lines must scope the namespace",
				"§10 step 3 (verify signature)", `add a quoted namespace, e.g. namespaces="git" (exactly what enroll emits)`)
		}
		for _, ns := range s.Namespaces {
			// An empty namespace value — namespaces="" or a trailing comma
			// (namespaces="git,") — matches like an omitted list but authorizes no
			// production operation (commit/attestation use non-empty names). Reject it
			// before resolving, so the check never PASSes a line the verifier rejects.
			if ns == "" {
				return fail(`candidate line has an empty namespace value (namespaces="" or a trailing comma) — no production verifier uses an empty namespace`,
					"§10 step 3 (verify signature)", `scope each namespace to a non-empty name, e.g. namespaces="git"`)
			}
			if _, rerr := sshsig.Resolve(s.Key, signers, ns, env.At); rerr != nil {
				return fail("candidate line parses but does not resolve in namespace "+ns+": "+rerr.Error(),
					"§10 step 3 (verify signature)", "check the namespace and the enrollment validity window")
			}
		}
	}
	return pass(fmt.Sprintf("candidate enrollment line resolves (%d signer(s))", len(signers)))
}

// ---- trust/ ----------------------------------------------------------------

func checkAgentProvenance(env *Env) Result {
	if env.Policy == nil {
		return skip("policy does not parse — meta-paths not resolvable")
	}
	meta := env.Policy.Meta.Paths
	if len(meta) == 0 {
		return skip("policy declares no meta paths")
	}
	commits, err := vcs.Range(env.Repo, "", "HEAD")
	if err != nil {
		return skip("cannot enumerate history: " + err.Error())
	}
	var agentMeta []string
	for _, c := range commits {
		if c.Trailers.Provenance() != "agent" {
			continue
		}
		for _, p := range c.Paths {
			if covered, cerr := trust.MetaPathCovers(meta, p); cerr == nil && covered {
				agentMeta = append(agentMeta, c.Hash[:12])
				break
			}
		}
	}
	if len(agentMeta) > 0 {
		return warn(fmt.Sprintf("%d trust-material commit(s) carry Provenance: agent (%s) — agent-authored meta changes need a human review to reach the required level",
			len(agentMeta), strings.Join(agentMeta, ", ")),
			"confirm each has a covering human review before release")
	}
	return pass("no agent-authored trust-material commits in history")
}

// ---- history/ --------------------------------------------------------------

func checkPreAdoption(env *Env) Result {
	// Pre-adoption triage applies only to a repository with no policy at all: an
	// unparseable or present policy is the adopted case (policy/parse owns it).
	if env.Policy != nil || env.PolicyErr != nil || len(env.PolicyRaw) > 0 {
		return skip("repository is adopted (a policy is present)")
	}
	commits, err := vcs.Range(env.Repo, "", "HEAD")
	if err != nil || len(commits) == 0 {
		return skip("no history to triage")
	}
	untrailered := 0
	for _, c := range commits {
		if c.Trailers.Provenance() == "" {
			untrailered++
		}
	}
	return warn(fmt.Sprintf("no policy at HEAD; %d/%d commits carry no Provenance trailer. While history is unshared, rebase-and-resign is a clean adoption; once shared, adopt with an adoption_boundary (ADR-026)",
		untrailered, len(commits)),
		"semver-trust doctor again after adding .semver-trust/policy.toml")
}

// ---- chain/ ----------------------------------------------------------------

func checkChainHead(env *Env) Result {
	if env.Descriptor == nil {
		return skip("no --bootstrap-descriptor supplied — the accepted chain head is descriptor-pinned (ADR-027/028) and not checkable without it")
	}
	if env.Policy == nil {
		return skip("policy does not parse — cannot build the attestation verifier")
	}
	// Mirror verify --chain-head (cmd/semver-trust/verify.go): this interval-less
	// reader bypasses the pipeline's checkPolicyTransition, so it must do the
	// §5.4/ADR-028 binding itself — authenticate the descriptor against HEAD's tree,
	// then bind the accepted chain to THIS descriptor's authority identity. Carrying
	// Bootstrap in the options also makes AttestationVerifier reject filesystem
	// trust-material overrides (a key-substitution bypass).
	opts := verify.Options{
		RepoPath:   env.Repo,
		To:         "HEAD",
		PolicyPath: env.PolicyPath,
		Component:  env.Descriptor.Component,
		VerifyTime: env.At,
		Bootstrap:  env.Descriptor,
	}
	// Authenticate the pinned policy/trust-material digests against HEAD BEFORE
	// trusting the store: a descriptor with the right repository/component but stale
	// or tampered digests must not produce a PASS.
	if err := verify.AuthenticateBootstrapTree(opts); err != nil {
		return fail("the bootstrap descriptor does not bind HEAD's tree: "+err.Error(),
			"§5.4/ADR-028 (descriptor binding)", "re-pin the descriptor to the committed policy/trust-material digests")
	}
	av, err := verify.AttestationVerifier(opts)
	if err != nil {
		return fail("cannot build the attestation verifier: "+err.Error(),
			"§9 (attestation)", "check the policy's attestation_signers")
	}
	if av == nil {
		return skip("policy declares no attestation signers — the accepted chain cannot be verified (§9)")
	}
	// Bind the reported head to descriptor.Digest() — the authority identity a
	// genesis release records — not merely a shared repository/component, so a
	// foreign descriptor sharing this subject cannot be reported as this chain's head.
	head, err := chain.AcceptedChainHeadBoundTo(env.Repo, env.Descriptor.Repository, env.Descriptor.Component, env.Descriptor.Digest(), av, env.At)
	if err != nil {
		return fail("the accepted chain does not verify or does not bind this descriptor: "+err.Error(),
			"§7.5/ADR-027 (accepted chain)", "inspect the release/v0.2 chain against the descriptor")
	}
	if head == nil {
		return skip("no accepted release/v0.2 chain head bound to this descriptor — genesis (no predecessor to project)")
	}
	return pass(fmt.Sprintf("accepted chain head: %s (effective %s)", head.Tag(), head.Effective()))
}

// ---- remote/platform/ ------------------------------------------------------

func checkFetchRefspec(env *Env) Result {
	// Require the exact mapping src:dst = refs/attestations/*:refs/attestations/*,
	// accepting the optional force prefix. A substring match would pass refspecs
	// that fetch into (or from) the wrong namespace — e.g. +refs/attestations/*:
	// refs/heads/attestations/* stores evidence where GitRefStore never reads it,
	// and +refs/heads/*:refs/attestations/* fetches no attestation refs at all —
	// so the diagnostic must not say verification will see evidence when it will not.
	const want = "refs/attestations/*:refs/attestations/*"
	for _, rs := range env.Git.FetchRefspecs {
		if strings.TrimPrefix(rs, "+") == want {
			return pass("attestation fetch refspec is configured")
		}
	}
	return warn("the attestation fetch refspec is not configured — `git fetch` will not move attestation evidence into the refs/attestations/* namespace the verifier reads (ADR-043)",
		`git config --add remote.origin.fetch '+refs/attestations/*:refs/attestations/*'`)
}

func checkRulesets(env *Env) Result {
	// Live branch-protection / ruleset enforcement is a platform fact no offline
	// tool can read (the cannot-check boundary); it is checked in CI, not here.
	return skip("live ruleset enforcement is a platform fact — not offline-checkable; run scripts/check-rulesets.py in CI")
}

func checkReleaseBaseline(env *Env) Result {
	tags, err := vcs.Tags(env.Repo)
	if err != nil {
		return skip("cannot read tags: " + err.Error())
	}
	if len(tags) == 0 {
		return skip("no tags yet — no release baseline (a first release anchors at root, or the adoption boundary)")
	}
	// Informational: doctor never decides a release; it points at the exact,
	// reproducible verify invocation. --from is the previous verified tag; --at
	// pins the recorded instant so the decision reproduces bit-for-bit.
	return pass(fmt.Sprintf("%d release tag(s); reproduce a release decision with: semver-trust verify --repo %s --from <prev-tag> --to <tag> --at <the tag's recorded predicate.timestamp>",
		len(tags), shellQuote(env.Repo)))
}
