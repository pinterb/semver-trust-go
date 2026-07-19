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
