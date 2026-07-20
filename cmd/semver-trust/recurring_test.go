// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/attest"
)

// recurringPolicy declares BOTH an allowed-signers registry (commit signing) and
// an attestation-signers registry (so a stored release/v0.2 is re-verifiable from
// TO's tree in v0.10 mode, which forbids the --attestation-signers override).
const recurringPolicy = `# semver-trust TEST POLICY - recurring-chain repo
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity]
attestation_signers = ".semver-trust/attestation_signers"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"
`

// treeAttestationSigners is the in-tree attestation-signer registry enrolling bob
// for the attestation namespace.
func treeAttestationSigners(t *testing.T) string {
	t.Helper()
	pub, err := os.ReadFile(bobKeyPath(t) + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return "bob@semver-trust.test namespaces=\"" + attest.Namespace + "\" " + strings.TrimSpace(string(pub)) + "\n"
}

// recurringDescriptor builds an inception bootstrap descriptor whose policy facts
// (incl. the attestation-signers registry) are derived from the repo's tree, so it
// authenticates by construction.
func recurringDescriptor(t *testing.T, repo string) map[string]any {
	t.Helper()
	digest, material, roles := policyFacts(t, repo, recurringPolicy)
	return map[string]any{
		"repository": "repo:test/widget", "component": "default",
		"interval_mode":        "inception",
		"policy_path":          ".semver-trust/policy.toml",
		"policy_digest":        digest,
		"trust_material":       material,
		"trust_roles":          roles,
		"verification_profile": "vp", "clock_profile": "cp",
		"version_predecessor": nil,
	}
}

// setupRecurringChain builds a repo with a genesis release/v0.2 and one later
// commit, returning the repo, descriptor path, and the founding / genesis-target /
// post-genesis commit SHAs.
func setupRecurringChain(t *testing.T) (repo, descPath, foundingCommit, genesisCommit, newCommit string) {
	t.Helper()
	keys := stageVendoredKeys(t)
	repo = t.TempDir()
	if out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	// Founding commit: policy + both trust registries.
	commitFilesSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test", map[string]string{
		".semver-trust/policy.toml":         recurringPolicy,
		".semver-trust/allowed_signers":     treeAllowedSigners(t),
		".semver-trust/attestation_signers": treeAttestationSigners(t),
	}, "feat: adopt semver-trust\n\nProvenance: human")
	foundingCommit = gitOut(t, repo, "rev-parse", "HEAD")
	// A feature commit that becomes the genesis release target.
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget\n", "feat: widget core\n\nProvenance: human")

	descPath = writeDescriptorFile(t, recurringDescriptor(t, repo))
	genesisCommit = gitOut(t, repo, "rev-parse", "HEAD")

	// Emit the GENESIS release/v0.2 (the B3 path): creates tag v0.1.0 at HEAD and
	// stores a bob-signed release/v0.2 attestation.
	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--predicate", "v0.2",
		"--repository-digest", "sha256:"+repoDigestHex,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t), "--attest-key", bobKeyPath(t),
		"--tagger-name", "alice", "--tagger-email", "alice@semver-trust.test",
		"--json")
	if err != nil {
		t.Fatalf("genesis release: %v\n%s", err, out)
	}

	// A new commit AFTER the genesis release — the recurring interval's content.
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget // v2\n", "feat: widget frobnicator\n\nProvenance: human")
	newCommit = gitOut(t, repo, "rev-parse", "HEAD")
	return repo, descPath, foundingCommit, genesisCommit, newCommit
}

// TestVerifyChainHead proves `verify --chain-head` fresh-verifies the v0.10 chain
// and reports the accepted head's tag + recorded effective trust — the verified
// object a release badge reads, rather than an unverified store blob. Here the head
// is the genesis v0.1.0 (clean, T2).
func TestVerifyChainHead(t *testing.T) {
	repo, descPath, _, genesisCommit, _ := setupRecurringChain(t)

	out, err := runCommand(t, "verify", "--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath, "--verify-time", releaseEpoch,
		"--chain-head", "--json")
	if err != nil {
		t.Fatalf("verify --chain-head: %v\n%s", err, out)
	}
	var head map[string]string
	if err := json.Unmarshal([]byte(out), &head); err != nil {
		t.Fatalf("chain-head JSON does not parse: %v\n%s", err, out)
	}
	if head["tag"] != "v0.1.0" {
		t.Errorf("chain head tag = %q, want v0.1.0 (the accepted head)", head["tag"])
	}
	if head["to_commit"] != genesisCommit {
		t.Errorf("chain head to_commit = %q, want the genesis commit %s", head["to_commit"], genesisCommit)
	}
	if head["effective"] != "T2" {
		t.Errorf("chain head effective = %q, want T2 (the head's recorded trust)", head["effective"])
	}
	if head["resulting_state_digest"] == "" {
		t.Error("chain head resulting_state_digest is empty")
	}

	// --chain-head without a descriptor is refused (it is the v0.10 authority).
	if _, e := runCommand(t, "verify", "--repo", repo, "--to", "main", "--chain-head"); e == nil {
		t.Error("verify --chain-head without --bootstrap-descriptor should be refused")
	}

	// A tampered descriptor is refused: --chain-head is self-contained — it
	// authenticates the descriptor's pinned digests against TO's tree itself
	// (§5.4/ADR-028), not merely on repository/component match.
	raw, err := os.ReadFile(descPath)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	d["policy_digest"] = "sha256:" + strings.Repeat("0", 64)
	b, _ := json.Marshal(d)
	badPath := t.TempDir() + "/bad-descriptor.json"
	if err := os.WriteFile(badPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, e := runCommand(t, "verify", "--repo", repo, "--to", "main",
		"--bootstrap-descriptor", badPath, "--verify-time", releaseEpoch, "--chain-head"); e == nil ||
		!strings.Contains(e.Error(), "does not bind") {
		t.Errorf("tampered descriptor: error = %v, want a tree-binding refusal", e)
	}

	// A FOREIGN descriptor — same repository/component and its policy/trust-material
	// still bind the tree, but different bytes (a different bootstrap authority
	// identity) — is rejected: the chain was not bootstrapped by it (§5.4/ADR-028),
	// even though everything about the current tree matches.
	var d2 map[string]any
	if err := json.Unmarshal(raw, &d2); err != nil {
		t.Fatal(err)
	}
	d2["verification_profile"] = "a-different-verifier" // changes the descriptor bytes, not the tree binding
	b2, _ := json.Marshal(d2)
	foreignPath := t.TempDir() + "/foreign-descriptor.json"
	if err := os.WriteFile(foreignPath, b2, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, e := runCommand(t, "verify", "--repo", repo, "--to", "main",
		"--bootstrap-descriptor", foreignPath, "--verify-time", releaseEpoch, "--chain-head"); e == nil ||
		!strings.Contains(e.Error(), "was not bootstrapped by the supplied descriptor") {
		t.Errorf("foreign descriptor: error = %v, want a bootstrap-authority refusal", e)
	}
}

// TestVerifyRecurringAdvance is the C2a payoff: after a genesis release/v0.2 and a
// later commit, verify DISCOVERS the accepted chain head and switches to the
// recurring path — the interval is P..TO (only the post-genesis commit, not the
// founding history) and the policy transition runs under the predecessor
// authority. No recurring release is emitted here (that is the release-side, C2b);
// this proves verify's recurrence detection and wiring.
func TestVerifyRecurringAdvance(t *testing.T) {
	repo, descPath, _, genesisCommit, newCommit := setupRecurringChain(t)

	// verify --to HEAD in v0.10 mode: discovers the genesis chain head → recurring.
	vout, err := runCommand(t, "verify",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--verify-time", releaseEpoch, "--json")
	if err != nil {
		t.Fatalf("recurring verify: %v\n%s", err, vout)
	}
	var report verifyReportJSON
	if err := json.Unmarshal([]byte(vout), &report); err != nil {
		t.Fatal(err)
	}

	// The policy transition ran under the PREDECESSOR authority (not bootstrap).
	if report.PolicyState == nil || report.PolicyState.Authority != "predecessor" {
		t.Errorf("policy_state authority = %+v, want the recurring predecessor authority", report.PolicyState)
	}
	if report.PolicyState != nil && report.PolicyState.AuthorityIdentity.URI != "predecessor:v0.1.0" {
		t.Errorf("authority_identity.uri = %q, want predecessor:v0.1.0", report.PolicyState.AuthorityIdentity.URI)
	}

	// The interval is P..TO: the new commit is classified; the genesis target and
	// the founding history are excluded (Reach(TO) − Reach(P)).
	classified := map[string]bool{}
	for _, c := range report.Commits {
		classified[c.SHA] = true
	}
	if !classified[newCommit] {
		t.Errorf("new commit %s not in the recurring interval", newCommit[:7])
	}
	if classified[genesisCommit] {
		t.Errorf("genesis target %s must be excluded from the recurring interval (P..TO)", genesisCommit[:7])
	}
	if len(report.Commits) != 1 {
		t.Errorf("recurring interval classified %d commits, want 1 (only the post-genesis commit)", len(report.Commits))
	}
	// Disclosure: anchored at the predecessor tag, not an adoption boundary.
	if report.From != "v0.1.0" || report.FromIsAdoptionBoundary {
		t.Errorf("from/boundary = %q/%v, want v0.1.0 / false", report.From, report.FromIsAdoptionBoundary)
	}
}

// TestVerifyRecurringRejectsCallerFromSkip proves a caller-supplied --from is NOT
// silently replaced with the accepted predecessor P: a recurring verify anchored
// at a non-predecessor revision (the founding commit, an ancestor of P) is refused
// (from_not_predecessor), so the §5.2/ADR-027 skip guard is reachable at the CLI.
func TestVerifyRecurringRejectsCallerFromSkip(t *testing.T) {
	repo, descPath, foundingCommit, _, _ := setupRecurringChain(t)

	out, err := runCommand(t, "verify",
		"--repo", repo, "--from", foundingCommit, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--verify-time", releaseEpoch, "--json")
	if err == nil {
		t.Fatalf("expected a from_not_predecessor refusal for a non-predecessor --from, got success:\n%s", out)
	}
	if !strings.Contains(err.Error(), "from_not_predecessor") {
		t.Errorf("error = %v, want a from_not_predecessor interval refusal", err)
	}
}

// TestVerifyRecurringAcceptsPredecessorFrom confirms the companion: pinning --from
// to the accepted predecessor (its tag) is a valid explicit continuation and
// verifies as recurring.
func TestVerifyRecurringAcceptsPredecessorFrom(t *testing.T) {
	repo, descPath, _, _, _ := setupRecurringChain(t)

	vout, err := runCommand(t, "verify",
		"--repo", repo, "--from", "v0.1.0", "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--verify-time", releaseEpoch, "--json")
	if err != nil {
		t.Fatalf("verify --from v0.1.0 (the predecessor): %v\n%s", err, vout)
	}
	var report verifyReportJSON
	if err := json.Unmarshal([]byte(vout), &report); err != nil {
		t.Fatal(err)
	}
	if report.PolicyState == nil || report.PolicyState.Authority != "predecessor" {
		t.Errorf("policy_state authority = %+v, want the recurring predecessor authority", report.PolicyState)
	}
}

// TestReleaseRecurringAdvanceEmitsChain is the C2b payoff: after a genesis
// release/v0.2, a RECURRING release advances the version line (v0.1.0 → v0.2.0)
// under the predecessor authority — binding the recurring interval, the
// predecessor attestation, the prior_state hash-chain link, and a chained
// resulting_state — and the chain then CONTINUES: a further commit + verify walks
// the full genesis→v0.2.0 chain (reproducing every state digest and link) and
// classifies the next interval under the v0.2.0 authority.
func TestReleaseRecurringAdvanceEmitsChain(t *testing.T) {
	repo, descPath, genesisFounding, genesisCommit, newCommit := setupRecurringChain(t)
	_ = genesisFounding

	// Emit the RECURRING release at newCommit: advances v0.1.0 → v0.2.0.
	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--predicate", "v0.2",
		"--repository-digest", "sha256:"+repoDigestHex,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t), "--attest-key", bobKeyPath(t),
		"--tagger-name", "alice", "--tagger-email", "alice@semver-trust.test",
		"--json")
	if err != nil {
		t.Fatalf("recurring release: %v\n%s", err, out)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Channel != "clean" || result.Tag != "v0.2.0" {
		t.Fatalf("recurring decision = %s/%s, want clean v0.2.0 (advance from v0.1.0)", result.Channel, result.Tag)
	}
	if result.VersionPredecessor == nil || *result.VersionPredecessor != "v0.1.0" {
		t.Errorf("version_predecessor = %v, want v0.1.0", result.VersionPredecessor)
	}

	// The stored recurring release/v0.2 binds the chain: advance (not genesis), the
	// predecessor tag, the recurring interval + predecessor_attestation, the
	// predecessor authority, and prior_state == the genesis resulting_state.digest.
	genesisDigest := storedResultingDigest(t, repo, "v0.1.0")
	succ := storedRecurringDoc(t, repo, "v0.2.0")
	vs := succ.Predicate.VersionState
	if vs.Genesis || vs.Action != "advance" {
		t.Errorf("version_state = genesis=%v action=%q, want false/advance", vs.Genesis, vs.Action)
	}
	if vs.Predecessor == nil || vs.Predecessor.Name != "v0.1.0" {
		t.Errorf("version_state.predecessor = %+v, want v0.1.0", vs.Predecessor)
	}
	if vs.PriorState == nil || vs.PriorState.Digest["sha256"] != genesisDigest {
		t.Errorf("prior_state.digest = %+v, want the genesis resulting digest %s", vs.PriorState, genesisDigest)
	}
	if succ.Predicate.Interval.Mode != "recurring" || succ.Predicate.Interval.PredecessorAttestation == nil {
		t.Errorf("interval = %+v, want recurring + a predecessor_attestation", succ.Predicate.Interval)
	}
	if succ.Predicate.PolicyState.Authority != "predecessor" {
		t.Errorf("policy_state.authority = %q, want predecessor", succ.Predicate.PolicyState.Authority)
	}
	// Unchanged recurring policy is the fixed point: no candidate is activated.
	if succ.Predicate.PolicyState.CandidatePolicy != nil || len(succ.Predicate.PolicyState.CandidateTrustRoots) != 0 {
		t.Errorf("unchanged recurring release bound candidate_policy=%v / %d candidate roots, want null/empty (candidate == active)",
			succ.Predicate.PolicyState.CandidatePolicy, len(succ.Predicate.PolicyState.CandidateTrustRoots))
	}

	// The chain CONTINUES: a further commit, then verify --to HEAD discovers v0.2.0
	// as the head, walks the full genesis→v0.2.0 chain (every digest + link
	// verified), and classifies the new interval under the v0.2.0 authority.
	keys := stageVendoredKeys(t)
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget // v3\n", "feat: widget v3\n\nProvenance: human")
	thirdCommit := gitOut(t, repo, "rev-parse", "HEAD")

	vout, err := runCommand(t, "verify",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--verify-time", releaseEpoch, "--json")
	if err != nil {
		t.Fatalf("verify after the recurring release (full chain walk): %v\n%s", err, vout)
	}
	var vr verifyReportJSON
	if err := json.Unmarshal([]byte(vout), &vr); err != nil {
		t.Fatal(err)
	}
	if vr.PolicyState == nil || vr.PolicyState.Authority != "predecessor" {
		t.Errorf("chain verify authority = %+v, want the v0.2.0 predecessor", vr.PolicyState)
	}
	if vr.From != "v0.2.0" {
		t.Errorf("chain verify from = %q, want v0.2.0 (the new head)", vr.From)
	}
	classified := map[string]bool{}
	for _, c := range vr.Commits {
		classified[c.SHA] = true
	}
	if !classified[thirdCommit] || classified[newCommit] || classified[genesisCommit] {
		t.Errorf("interval after v0.2.0 = %v, want only the third commit %s", classified, thirdCommit[:7])
	}
}

// storedResultingDigest reads the release/v0.2 stored under tag and returns its
// version_state.resulting_state sha256 digest.
func storedResultingDigest(t *testing.T, repo, tag string) string {
	t.Helper()
	return storedRecurringDoc(t, repo, tag).Predicate.VersionState.ResultingState.Digest["sha256"]
}

// storedRecurringDoc reads and decodes the release/v0.2 stored under tag.
func storedRecurringDoc(t *testing.T, repo, tag string) recurringReleaseDoc {
	t.Helper()
	byTag, err := (attest.GitRefStore{Path: repo}).List(tag)
	if err != nil || len(byTag) != 1 {
		t.Fatalf("stored envelopes under %q = %d (%v), want 1", tag, len(byTag), err)
	}
	var doc recurringReleaseDoc
	if err := json.Unmarshal(envelopePayload(t, byTag[0]), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// recurringReleaseDoc is the subset of a release/v0.2 payload the chain assertions
// read.
type recurringReleaseDoc struct {
	Predicate struct {
		Interval struct {
			Mode                   string           `json:"mode"`
			PredecessorAttestation *json.RawMessage `json:"predecessor_attestation"`
		} `json:"interval"`
		PolicyState struct {
			Authority           string            `json:"authority"`
			CandidatePolicy     *json.RawMessage  `json:"candidate_policy"`
			CandidateTrustRoots []json.RawMessage `json:"candidate_trust_roots"`
		} `json:"policy_state"`
		VersionState struct {
			Genesis     bool   `json:"genesis"`
			Action      string `json:"action"`
			Predecessor *struct {
				Name string `json:"name"`
			} `json:"predecessor"`
			PriorState *struct {
				Digest map[string]string `json:"digest"`
			} `json:"prior_state"`
			ResultingState struct {
				Digest map[string]string `json:"digest"`
			} `json:"resulting_state"`
		} `json:"version_state"`
	} `json:"predicate"`
}

// verifyReportJSON is the subset of the verify --json report the recurring test
// asserts on.
type verifyReportJSON struct {
	From                   string `json:"from"`
	FromIsAdoptionBoundary bool   `json:"from_is_adoption_boundary"`
	Commits                []struct {
		SHA string `json:"sha"`
	} `json:"commits"`
	PolicyState *struct {
		Authority         string `json:"authority"`
		AuthorityIdentity struct {
			URI string `json:"uri"`
		} `json:"authority_identity"`
	} `json:"policy_state"`
}
