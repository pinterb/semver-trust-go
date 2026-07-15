// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// adoptionPolicy is the ADR-026 single-maintainer policy used by the ancestry
// repo: T2 threshold, demote, boundary at v0-import.
const adoptionPolicy = `# semver-trust TEST POLICY - version-ancestry adoption repo
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"
adoption_boundary = "v0-import"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"
`

// buildAdoptionAncestryRepo builds a legacy repo that adopts the scheme:
//
//	C_leg (tag v1.4.0) ── C_bnd (tag v0-import, boundary) ── alice (adopts, HEAD)
//
// The pre-boundary commits are excluded from verification (adoption), so a
// bootstrap descriptor can authenticate v1.4.0 as the version predecessor even
// though its commit predates the scheme. Returns the repo path plus the legacy
// and boundary commit OIDs.
func buildAdoptionAncestryRepo(t *testing.T) (repo, legacyCommit, boundaryCommit string) {
	t.Helper()
	keys := stageVendoredKeys(t)
	repo = t.TempDir()
	if out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	commitSignedCLI(t, repo, keys, "unknown-mallory", "mallory@semver-trust.test",
		"legacy.txt", "legacy v1.4.0 content\n", "chore: legacy release 1.4.0\n\nProvenance: human")
	gitCLI(t, repo, "tag", "v1.4.0")
	legacyCommit = gitOut(t, repo, "rev-parse", "v1.4.0")

	commitSignedCLI(t, repo, keys, "unknown-mallory", "mallory@semver-trust.test",
		"pre.txt", "pre-scheme content\n", "feat: pre-scheme change\n\nProvenance: human")
	gitCLI(t, repo, "tag", "v0-import")
	boundaryCommit = gitOut(t, repo, "rev-parse", "v0-import")

	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		".semver-trust/policy.toml", adoptionPolicy, "feat: adopt semver-trust (ADR-026)\n\nProvenance: human")
	return repo, legacyCommit, boundaryCommit
}

func gitOut(t *testing.T, repo string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// TestReleaseVersionAncestryContinuesLine is the go#70 regression: the very repo
// that restarts to v0.1.0 without a descriptor (TestReleaseAdoptionBoundaryDisclosed)
// continues the authenticated version line to v1.5.0 when a bootstrap descriptor
// supplies v1.4.0 as the version predecessor — and does so from the descriptor,
// not from --from (which is never passed). This is the disclosure/continuity fix
// (§7.5/ADR-029): the version predecessor is an authenticated fact, and the
// boundary release no longer restarts the line.
func TestReleaseVersionAncestryContinuesLine(t *testing.T) {
	repo, legacyCommit, boundaryCommit := buildAdoptionAncestryRepo(t)

	descriptor := map[string]any{
		"repository": "repo:test/widget",
		// The descriptor component MUST be the released/attested component: this
		// single-component repo scopes to "default", so the version authority and
		// the emitted predicate bind the same component chain (§5.4).
		"component":     "default",
		"interval_mode": "adoption",
		"boundary":      map[string]any{"oid": boundaryCommit, "ref_target": boundaryCommit},
		"tag_prefix":    "",
		"policy_path":   ".semver-trust/policy.toml",
		// The version evaluator does not check the policy digest (that is the
		// policy-transition milestone); a format-valid placeholder suffices here.
		"policy_digest":        "sha256:" + strings.Repeat("a", 64),
		"verification_profile": "vp",
		"clock_profile":        "cp",
		"version_predecessor": map[string]any{
			"tag": "v1.4.0", "ref_oid": legacyCommit, "commit_oid": legacyCommit,
		},
	}
	descPath := filepath.Join(t.TempDir(), "bootstrap.json") // out-of-band: not inside repo
	data, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runCommand(t, "release",
		"--repo", repo,
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--bootstrap-descriptor", descPath,
		"--claimed-bump", "minor",
		"--blast", "low",
		"--verify-time", releaseEpoch,
		"--dry-run",
		"--json")
	if err != nil {
		t.Fatalf("release: %v\n%s", err, out)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}

	// Without a descriptor this repo cuts v0.1.0 from the v0.0.0 baseline
	// (TestReleaseAdoptionBoundaryDisclosed). With the authenticated v1.4.0
	// predecessor, the line continues: 1.4.0 + minor = 1.5.0, clean at T2×low.
	if result.Channel != "clean" || result.Tag != "v1.5.0" {
		t.Errorf("decision = channel %s tag %s; want clean v1.5.0 (continued line, not a v0.x restart)", result.Channel, result.Tag)
	}
	if !result.VersionAuthenticated {
		t.Error("version_authenticated = false; the descriptor should have governed the version line")
	}
	if result.VersionPredecessor == nil || *result.VersionPredecessor != "v1.4.0" {
		t.Errorf("version_predecessor = %v, want the authenticated v1.4.0", result.VersionPredecessor)
	}

	// The version authority and the emitted predicate must bind the same
	// component chain: descriptor component "default" == predicate component.
	var stmt releasePayloadJSON
	if err := json.Unmarshal(result.Statement, &stmt); err != nil {
		t.Fatal(err)
	}
	if stmt.Predicate.Component != "default" {
		t.Errorf("predicate component = %q, want %q (the descriptor's component)", stmt.Predicate.Component, "default")
	}
}

// TestReleaseVersionAncestryRejectsIterationOverride confirms a caller-selected
// iteration is refused in v0.10 mode: the iteration is authenticated by the
// version ancestry (§7.5), never taken from --iteration.
func TestReleaseVersionAncestryRejectsIterationOverride(t *testing.T) {
	repo, legacyCommit, boundaryCommit := buildAdoptionAncestryRepo(t)
	descriptor := map[string]any{
		"repository": "repo:test/widget", "component": "default",
		"interval_mode":        "adoption",
		"boundary":             map[string]any{"oid": boundaryCommit, "ref_target": boundaryCommit},
		"policy_path":          ".semver-trust/policy.toml",
		"policy_digest":        "sha256:" + strings.Repeat("a", 64),
		"verification_profile": "vp", "clock_profile": "cp",
		"version_predecessor": map[string]any{"tag": "v1.4.0", "ref_oid": legacyCommit, "commit_oid": legacyCommit},
	}
	descPath := filepath.Join(t.TempDir(), "bootstrap.json")
	data, _ := json.Marshal(descriptor)
	if err := os.WriteFile(descPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--bootstrap-descriptor", descPath,
		"--claimed-bump", "minor", "--blast", "low",
		"--iteration", "9",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err == nil {
		t.Fatalf("expected refusal for --iteration in v0.10 mode, got success:\n%s", out)
	}
	if !strings.Contains(err.Error(), "iteration") {
		t.Errorf("error = %v, want an iteration-override rejection", err)
	}
}

// TestReleaseVersionAncestryRejectsInRepoDescriptor confirms the opt-in gate's
// out-of-band guard reaches the release path: a descriptor inside the repo is
// refused rather than trusted.
func TestReleaseVersionAncestryRejectsInRepoDescriptor(t *testing.T) {
	repo, _, _ := buildAdoptionAncestryRepo(t)
	inRepo := filepath.Join(repo, "bootstrap.json")
	if err := os.WriteFile(inRepo, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--bootstrap-descriptor", inRepo,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err == nil {
		t.Fatalf("expected refusal for an in-repo descriptor, got success:\n%s", out)
	}
	if !strings.Contains(err.Error(), "out-of-band") {
		t.Errorf("error = %v, want an out-of-band rejection", err)
	}
}
