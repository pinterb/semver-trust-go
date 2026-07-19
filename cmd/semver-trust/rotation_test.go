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

// signerLine returns the vendored allowed-signers registry line for identity.
func signerLine(t *testing.T, identity string) string {
	t.Helper()
	data, err := os.ReadFile(allowedSignersPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, identity+" ") {
			return line
		}
	}
	t.Fatalf("no allowed-signers line for %s", identity)
	return ""
}

// setupRotationChain builds a repo whose genesis registry enrolls only alice,
// emits a genesis release/v0.2, then commits a two-stage KEY ROTATION that adds
// bob to the human allowed-signers (a trust-material change, alice-signed). If
// bobCommit is set, it also adds a commit signed by the newly-added bob key — a
// candidate-only key signing the interval it is being enrolled in. Returns the
// repo and descriptor path.
func setupRotationChain(t *testing.T, bobCommit bool) (repo, descPath string) {
	t.Helper()
	keys := stageVendoredKeys(t)
	repo = t.TempDir()
	if out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	aliceOnly := signerLine(t, "alice@semver-trust.test") + "\n"
	aliceAndBob := aliceOnly + signerLine(t, "bob@semver-trust.test") + "\n"

	// Founding: policy + an ALICE-ONLY human registry + bob's attestation registry.
	commitFilesSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test", map[string]string{
		".semver-trust/policy.toml":         recurringPolicy,
		".semver-trust/allowed_signers":     aliceOnly,
		".semver-trust/attestation_signers": treeAttestationSigners(t),
	}, "feat: adopt semver-trust\n\nProvenance: human")
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget\n", "feat: widget core\n\nProvenance: human")

	descPath = writeDescriptorFile(t, recurringDescriptor(t, repo))

	// GENESIS release v0.1.0 under the alice-only authority.
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

	// The ROTATION: alice (the old, active human) enrolls bob in the human registry
	// (a two-stage rotation — bob activates for the NEXT interval).
	commitFilesSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test", map[string]string{
		".semver-trust/allowed_signers": aliceAndBob,
	}, "chore: enroll bob (key rotation)\n\nProvenance: human")

	if bobCommit {
		// A candidate-only key (bob) signs a commit in the very interval that
		// enrolls it — the two-stage rule must reject this (unknown_active_signer).
		commitSignedCLI(t, repo, keys, "human-bob", "bob@semver-trust.test",
			"widget.go", "package widget // bob\n", "feat: bob change\n\nProvenance: human")
	} else {
		// An ordinary alice-signed feature commit (old authority).
		commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
			"widget.go", "package widget // v2\n", "feat: widget frobnicator\n\nProvenance: human")
	}
	return repo, descPath
}

// TestReleaseRecurringPolicyRotation is the C3 payoff: a recurring release across a
// two-stage key rotation. The interval is verified under the OLD (active) authority
// read from the predecessor's tree, and the NEW policy is bound as the candidate
// activated for the next interval.
func TestReleaseRecurringPolicyRotation(t *testing.T) {
	repo, descPath := setupRotationChain(t, false)

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
		t.Fatalf("recurring rotation release: %v\n%s", err, out)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Channel != "clean" || result.Tag != "v0.2.0" {
		t.Fatalf("rotation decision = %s/%s, want clean v0.2.0", result.Channel, result.Tag)
	}

	// The stored release binds the predecessor authority AND a candidate policy
	// (the rotated policy activated for the next interval); active != candidate.
	doc := storedRotationDoc(t, repo, "v0.2.0")
	if doc.Predicate.PolicyState.Authority != "predecessor" {
		t.Errorf("policy_state.authority = %q, want predecessor", doc.Predicate.PolicyState.Authority)
	}
	if doc.Predicate.PolicyState.CandidatePolicy == nil {
		t.Errorf("candidate_policy is null, want the rotated policy activated for the next interval")
	}
	if len(doc.Predicate.PolicyState.CandidateTrustRoots) == 0 {
		t.Errorf("candidate_trust_roots is empty, want the rotated human registry")
	}
}

// TestVerifyRecurringRotationRejectsCandidateOnlyKey proves the two-stage rule:
// a candidate-only key (bob, enrolled in the SAME interval) that signs a commit in
// that interval is refused (unknown_active_signer) — new roots activate only for
// the NEXT interval (ADR-028).
func TestVerifyRecurringRotationRejectsCandidateOnlyKey(t *testing.T) {
	repo, descPath := setupRotationChain(t, true)

	out, err := runCommand(t, "verify",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--verify-time", releaseEpoch, "--json")
	if err == nil {
		t.Fatalf("expected an unknown_active_signer refusal for a candidate-only signer, got success:\n%s", out)
	}
	if !strings.Contains(err.Error(), "unknown_active_signer") {
		t.Errorf("error = %v, want an unknown_active_signer transition refusal", err)
	}
}

// storedRotationDoc reads the release/v0.2 stored under tag and decodes the
// policy_state fields the rotation test asserts on.
func storedRotationDoc(t *testing.T, repo, tag string) rotationReleaseDoc {
	t.Helper()
	byTag, err := (attest.GitRefStore{Path: repo}).List(tag)
	if err != nil || len(byTag) != 1 {
		t.Fatalf("stored envelopes under %q = %d (%v), want 1", tag, len(byTag), err)
	}
	var doc rotationReleaseDoc
	if err := json.Unmarshal(envelopePayload(t, byTag[0]), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

type rotationReleaseDoc struct {
	Predicate struct {
		PolicyState struct {
			Authority           string           `json:"authority"`
			CandidatePolicy     *json.RawMessage `json:"candidate_policy"`
			CandidateTrustRoots []struct {
				Path string `json:"path"`
			} `json:"candidate_trust_roots"`
		} `json:"policy_state"`
	} `json:"predicate"`
}
