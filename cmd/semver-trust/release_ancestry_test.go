// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/verify"
)

// adoptionPolicy is the single-maintainer policy used by the ancestry repo: T2
// threshold, demote. In v0.10 mode the adoption boundary is a descriptor fact
// (ADR-028 supersedes the ADR-026 policy adoption_boundary), so the policy does
// not declare one. It declares in-tree trust material so the §5.4 policy
// transition can digest-pin it (M3).
const adoptionPolicy = `# semver-trust TEST POLICY - version-ancestry adoption repo
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"
`

// commitFilesSignedCLI writes several files and commits them in one SSH-signed
// commit — the boundary/adopting commit carries both the policy and its in-tree
// trust material.
func commitFilesSignedCLI(t *testing.T, repo, keys, key, identity string, files map[string]string, message string) {
	t.Helper()
	for file, content := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, file)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, file), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		gitCLI(t, repo, "add", file)
	}
	gitCLI(t, repo,
		"-c", "user.name="+strings.SplitN(identity, "@", 2)[0],
		"-c", "user.email="+identity,
		"-c", "gpg.format=ssh",
		"-c", "user.signingkey="+filepath.Join(keys, key),
		"-c", "commit.gpgsign=true",
		"commit", "--quiet", "-m", message)
}

// treeAllowedSigners is the vendored allowed-signers registry committed in-tree
// so the policy's identity.human.allowed_signers resolves from TO's tree and the
// transition can digest-pin it.
func treeAllowedSigners(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(allowedSignersPath(t))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

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

	// The pre-scheme legacy release (mallory, unverifiable): excluded from the
	// interval as a parent of the boundary, but the authenticated version
	// predecessor v1.4.0.
	commitSignedCLI(t, repo, keys, "unknown-mallory", "mallory@semver-trust.test",
		"legacy.txt", "legacy v1.4.0 content\n", "chore: legacy release 1.4.0\n\nProvenance: human")
	gitCLI(t, repo, "tag", "v1.4.0")
	legacyCommit = gitOut(t, repo, "rev-parse", "v1.4.0")

	// The boundary IS the adopting commit — alice-signed, carrying the policy
	// and its in-tree trust registry, so under ADR-027 it is included in the
	// interval and itself verifies (earliest verifiable commit).
	commitFilesSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test", map[string]string{
		".semver-trust/policy.toml":     adoptionPolicy,
		".semver-trust/allowed_signers": treeAllowedSigners(t),
	}, "feat: adopt semver-trust (ADR-026)\n\nProvenance: human")
	gitCLI(t, repo, "tag", "v0-import")
	boundaryCommit = gitOut(t, repo, "rev-parse", "v0-import")

	// A post-boundary feat at TO, so the interval is more than the boundary.
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget\n", "feat: widget core\n\nProvenance: human")
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
	descPath := writeDescriptorFile(t, adoptionDescriptor(t, repo, boundaryCommit, boundaryCommit, legacyCommit))

	out, err := runCommand(t, "release",
		"--repo", repo,
		"--to", "main",
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

	// ADR-027: the boundary commit is INCLUDED in the interval and itself
	// verified; the pre-boundary legacy commit is excluded.
	classified := map[string]bool{}
	for _, c := range result.Report.Commits {
		classified[c.SHA] = true
	}
	if !classified[boundaryCommit] {
		t.Errorf("boundary %s not in the classified interval — ADR-027 includes and verifies it", boundaryCommit[:7])
	}
	if classified[legacyCommit] {
		t.Errorf("pre-boundary legacy %s must be excluded from the interval", legacyCommit[:7])
	}
}

// TestReleaseVersionAncestryRejectsIterationOverride confirms a caller-selected
// iteration is refused in v0.10 mode: the iteration is authenticated by the
// version ancestry (§7.5), never taken from --iteration.
func TestReleaseVersionAncestryRejectsIterationOverride(t *testing.T) {
	repo, legacyCommit, boundaryCommit := buildAdoptionAncestryRepo(t)
	descPath := writeDescriptorFile(t, adoptionDescriptor(t, repo, boundaryCommit, boundaryCommit, legacyCommit))
	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
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

const inceptionPolicy = `# semver-trust TEST POLICY - version-ancestry inception repo
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"
`

// buildInceptionRepo is a greenfield repo adopting the scheme from inception:
// alice's founding policy + in-tree trust registry commit plus a feature commit,
// no legacy history and no boundary.
func buildInceptionRepo(t *testing.T) string {
	t.Helper()
	keys := stageVendoredKeys(t)
	repo := t.TempDir()
	if out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	commitFilesSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test", map[string]string{
		".semver-trust/policy.toml":     inceptionPolicy,
		".semver-trust/allowed_signers": treeAllowedSigners(t),
	}, "feat: adopt semver-trust\n\nProvenance: human")
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget\n", "feat: widget core\n\nProvenance: human")
	return repo
}

// policyFacts derives the authenticated policy facts (§5.4) a bootstrap
// descriptor must pin — the sha256:-prefixed policy digest and the digest-pinned
// trust material / roles — from TO's tree via the same producer the verifier
// uses, so the descriptor authenticates by construction.
func policyFacts(t *testing.T, repo, policyTOML string) (digest string, material, roles map[string]string) {
	t.Helper()
	pol, err := policy.Parse([]byte(policyTOML))
	if err != nil {
		t.Fatal(err)
	}
	mp, err := verify.MetaPolicyFromTree(pol, ".semver-trust/policy.toml", repo, "main")
	if err != nil {
		t.Fatalf("MetaPolicyFromTree: %v", err)
	}
	return mp.Digest, mp.TrustMaterial, mp.TrustRoles
}

// adoptionDescriptor builds an adoption bootstrap descriptor pinning the given
// boundary (oid/ref_target), version predecessor, and the repo's authenticated
// policy facts.
func adoptionDescriptor(t *testing.T, repo, boundaryOID, boundaryRefTarget, predecessorCommit string) map[string]any {
	t.Helper()
	digest, material, roles := policyFacts(t, repo, adoptionPolicy)
	return map[string]any{
		"repository": "repo:test/widget", "component": "default",
		"interval_mode":        "adoption",
		"boundary":             map[string]any{"oid": boundaryOID, "ref_target": boundaryRefTarget},
		"policy_path":          ".semver-trust/policy.toml",
		"policy_digest":        digest,
		"trust_material":       material,
		"trust_roles":          roles,
		"verification_profile": "vp", "clock_profile": "cp",
		"version_predecessor": map[string]any{"tag": "v1.4.0", "ref_oid": predecessorCommit, "commit_oid": predecessorCommit},
	}
}

// inceptionDescriptor builds an inception bootstrap descriptor (no boundary, null
// version predecessor) with the repo's authenticated policy facts.
func inceptionDescriptor(t *testing.T, repo string) map[string]any {
	t.Helper()
	digest, material, roles := policyFacts(t, repo, inceptionPolicy)
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

// writeDescriptorFile marshals a descriptor to an out-of-band temp file (never
// inside the repo) and returns its path.
func writeDescriptorFile(t *testing.T, descriptor map[string]any) string {
	t.Helper()
	descPath := filepath.Join(t.TempDir(), "bootstrap.json")
	data, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(descPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return descPath
}

// TestReleaseVersionAncestryInception cuts a v0.10 inception release: no
// boundary, an explicit null version predecessor, so the interval is the whole
// reachable history (root..TO) and the version line starts fresh at v0.1.0.
func TestReleaseVersionAncestryInception(t *testing.T) {
	repo := buildInceptionRepo(t)
	descPath := writeDescriptorFile(t, inceptionDescriptor(t, repo))
	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err != nil {
		t.Fatalf("release: %v\n%s", err, out)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.Channel != "clean" || result.Tag != "v0.1.0" {
		t.Errorf("inception decision = channel %s tag %s; want clean v0.1.0 (fresh line)", result.Channel, result.Tag)
	}
	if result.VersionPredecessor != nil {
		t.Errorf("version_predecessor = %v, want none (null predecessor)", *result.VersionPredecessor)
	}
	if len(result.Report.Commits) != 2 {
		t.Errorf("inception interval classified %d commits, want 2 (root..TO)", len(result.Report.Commits))
	}
}

// TestReleaseVersionAncestryRejectsCallerFrom confirms a caller-selected --from
// is refused in v0.10 genesis mode: the interval is authenticated, not
// caller-anchored (SelectInterval returns untrusted_from).
func TestReleaseVersionAncestryRejectsCallerFrom(t *testing.T) {
	repo, legacyCommit, boundaryCommit := buildAdoptionAncestryRepo(t)
	descPath := writeDescriptorFile(t, adoptionDescriptor(t, repo, boundaryCommit, boundaryCommit, legacyCommit))
	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--from", "v0-import",
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err == nil {
		t.Fatalf("expected refusal for a caller --from in v0.10 mode, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "untrusted_from") {
		t.Errorf("error = %v, want untrusted_from", err)
	}
}

// TestReleaseVersionAncestryRejectsMovedBoundary confirms an adoption boundary
// whose ref no longer resolves to its pinned OID is refused (boundary_ref_moved).
func TestReleaseVersionAncestryRejectsMovedBoundary(t *testing.T) {
	repo, legacyCommit, boundaryCommit := buildAdoptionAncestryRepo(t)
	// ref_target != oid: the pinned boundary ref has moved.
	descPath := writeDescriptorFile(t, adoptionDescriptor(t, repo, boundaryCommit, legacyCommit, legacyCommit))
	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err == nil {
		t.Fatalf("expected refusal for a moved boundary ref, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "boundary_ref_moved") {
		t.Errorf("error = %v, want boundary_ref_moved", err)
	}
}

// TestVerifyVersionAncestryRejectsComponentMismatch confirms the §5.4 subject
// binding is enforced in the standalone verify command too (not only the release
// decision path): a descriptor whose component is not the verified component is
// refused.
func TestVerifyVersionAncestryRejectsComponentMismatch(t *testing.T) {
	repo, legacyCommit, boundaryCommit := buildAdoptionAncestryRepo(t)
	desc := adoptionDescriptor(t, repo, boundaryCommit, boundaryCommit, legacyCommit)
	desc["component"] = "other" // the repo's actual component is "default"
	descPath := writeDescriptorFile(t, desc)
	out, err := runCommand(t, "verify",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--verify-time", releaseEpoch, "--json")
	if err == nil {
		t.Fatalf("expected verify to reject a component-mismatched descriptor, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "subject binding") {
		t.Errorf("error = %v, want a §5.4 subject-binding rejection", err)
	}
}

// TestReleaseVersionAncestryRejectsPolicyDigestMismatch: the descriptor's pinned
// policy digest must equal TO's policy (§5.4/ADR-028), or the genesis policy is
// not authenticated.
func TestReleaseVersionAncestryRejectsPolicyDigestMismatch(t *testing.T) {
	repo, legacyCommit, boundaryCommit := buildAdoptionAncestryRepo(t)
	desc := adoptionDescriptor(t, repo, boundaryCommit, boundaryCommit, legacyCommit)
	desc["policy_digest"] = "sha256:" + strings.Repeat("b", 64) // does not match TO's policy
	descPath := writeDescriptorFile(t, desc)
	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err == nil {
		t.Fatalf("expected refusal for a mismatched policy digest, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "bootstrap_policy_mismatch") {
		t.Errorf("error = %v, want bootstrap_policy_mismatch", err)
	}
}

// TestReleaseVersionAncestryRejectsTrustMaterialMismatch: the descriptor's pinned
// trust-material digests must match the bytes in TO's tree.
func TestReleaseVersionAncestryRejectsTrustMaterialMismatch(t *testing.T) {
	repo, legacyCommit, boundaryCommit := buildAdoptionAncestryRepo(t)
	desc := adoptionDescriptor(t, repo, boundaryCommit, boundaryCommit, legacyCommit)
	material := desc["trust_material"].(map[string]string)
	for k := range material {
		material[k] = "sha256:" + strings.Repeat("c", 64) // corrupt the pinned digest
	}
	descPath := writeDescriptorFile(t, desc)
	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--claimed-bump", "minor", "--blast", "low",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err == nil {
		t.Fatalf("expected refusal for mismatched trust-material digests, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "bootstrap_trust_material_mismatch") {
		t.Errorf("error = %v, want bootstrap_trust_material_mismatch", err)
	}
}

// TestVerifyVersionAncestryRejectsTrustMaterialOverride closes the go#97 bypass:
// in v0.10 mode a filesystem --allowed-signers override would let unpinned
// material verify commits while the transition only checks the descriptor-pinned
// tree bytes (key substitution under an authorized principal). The override is
// refused fail-fast, so the material used for verification IS what the descriptor
// pins.
func TestVerifyVersionAncestryRejectsTrustMaterialOverride(t *testing.T) {
	repo, legacyCommit, boundaryCommit := buildAdoptionAncestryRepo(t)
	descPath := writeDescriptorFile(t, adoptionDescriptor(t, repo, boundaryCommit, boundaryCommit, legacyCommit))
	out, err := runCommand(t, "verify",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--allowed-signers", allowedSignersPath(t),
		"--verify-time", releaseEpoch, "--json")
	if err == nil {
		t.Fatalf("expected verify to reject a trust-material override in v0.10 mode, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "overrides the descriptor-pinned trust material") {
		t.Errorf("error = %v, want a trust-material override rejection", err)
	}
}
