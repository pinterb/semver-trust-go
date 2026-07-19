// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

const agentTrailer = "Provenance: agent\nProvenance-Agent: claude-code/test\nProvenance-Model: test"

// setupPrereleaseChain builds a chain whose genesis is an UNPROMOTED prerelease:
// an unreviewed agent commit floors the scope to T0, so the genesis release is
// v0.1.0-t0.1 (a prerelease target, not the clean channel). A later agent commit
// gives the recut interval its source. Returns the repo and descriptor path.
func setupPrereleaseChain(t *testing.T) (repo, descPath string) {
	t.Helper()
	keys := stageVendoredKeys(t)
	repo = t.TempDir()
	if out, err := exec.Command("git", "-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}

	// Founding: policy + registries, alice-human (T2 — it touches the meta paths).
	commitFilesSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test", map[string]string{
		".semver-trust/policy.toml":         recurringPolicy,
		".semver-trust/allowed_signers":     treeAllowedSigners(t),
		".semver-trust/attestation_signers": treeAttestationSigners(t),
	}, "feat: adopt semver-trust\n\nProvenance: human")
	// An UNREVIEWED agent commit → T0, flooring the scope to a prerelease.
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget\n", "feat: widget core\n\n"+agentTrailer)

	descPath = writeDescriptorFile(t, recurringDescriptor(t, repo))

	// GENESIS release: T0 effective → prerelease v0.1.0-t0.1.
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
		t.Fatalf("genesis prerelease: %v\n%s", err, out)
	}
	var g releaseResultJSON
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatal(err)
	}
	if g.Channel != "prerelease" || g.Tag != "v0.1.0-t0.1" {
		t.Fatalf("genesis = %s/%s, want prerelease v0.1.0-t0.1 (an unpromoted target to re-cut)", g.Channel, g.Tag)
	}

	// More source for the recut interval (still unreviewed agent → T0).
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget // more\n", "fix: widget tweak\n\n"+agentTrailer)
	return repo, descPath
}

// TestReleaseRecurringRecut is the C4 payoff: re-cutting an unpromoted prerelease
// target. The core is PRESERVED (0.1.0) and the iteration advances (t0.1 → t0.2);
// the successor binds action=recut, the predecessor tag, and chains prior_state to
// the predecessor's resulting_state.
func TestReleaseRecurringRecut(t *testing.T) {
	repo, descPath := setupPrereleaseChain(t)

	out, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--predicate", "v0.2", "--action", "recut",
		"--repository-digest", "sha256:"+repoDigestHex,
		"--claimed-bump", "patch", "--blast", "low",
		"--verify-time", releaseEpoch,
		"--tag-key", bobKeyPath(t), "--attest-key", bobKeyPath(t),
		"--tagger-name", "alice", "--tagger-email", "alice@semver-trust.test",
		"--json")
	if err != nil {
		t.Fatalf("recut release: %v\n%s", err, out)
	}
	var result releaseResultJSON
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	// Recut preserves the core (0.1.0) and advances the iteration (t0.1 → t0.2).
	if result.Channel != "prerelease" || result.Tag != "v0.1.0-t0.2" {
		t.Fatalf("recut decision = %s/%s, want prerelease v0.1.0-t0.2 (same core, next iteration)", result.Channel, result.Tag)
	}

	genesisDigest := storedResultingDigest(t, repo, "v0.1.0-t0.1")
	doc := storedRecurringDoc(t, repo, "v0.1.0-t0.2")
	vs := doc.Predicate.VersionState
	if vs.Genesis || vs.Action != "recut" {
		t.Errorf("version_state = genesis=%v action=%q, want false/recut", vs.Genesis, vs.Action)
	}
	if vs.Predecessor == nil || vs.Predecessor.Name != "v0.1.0-t0.1" {
		t.Errorf("version_state.predecessor = %+v, want the re-cut target v0.1.0-t0.1", vs.Predecessor)
	}
	if vs.PriorState == nil || vs.PriorState.Digest["sha256"] != genesisDigest {
		t.Errorf("prior_state.digest = %+v, want the genesis resulting digest %s", vs.PriorState, genesisDigest)
	}

	// The chain continues and re-verifies end to end: a further agent commit, then
	// verify --to HEAD walks v0.1.0-t0.1 → v0.1.0-t0.2 and classifies the next
	// interval under the v0.1.0-t0.2 authority.
	keys := stageVendoredKeys(t)
	commitSignedCLI(t, repo, keys, "human-alice", "alice@semver-trust.test",
		"widget.go", "package widget // v3\n", "fix: widget v3\n\n"+agentTrailer)

	vout, verr := runCommand(t, "verify",
		"--repo", repo, "--to", "main",
		"--bootstrap-descriptor", descPath,
		"--verify-time", releaseEpoch, "--json")
	if verr != nil {
		t.Fatalf("verify after recut (chain walk): %v\n%s", verr, vout)
	}
	var vr verifyReportJSON
	if err := json.Unmarshal([]byte(vout), &vr); err != nil {
		t.Fatal(err)
	}
	if vr.From != "v0.1.0-t0.2" {
		t.Errorf("chain verify from = %q, want v0.1.0-t0.2 (the recut head)", vr.From)
	}
}

// TestReleaseRecutRequiresDescriptor confirms --action recut is refused without the
// v0.10 authority (it re-cuts an accepted predecessor).
func TestReleaseRecutRequiresDescriptor(t *testing.T) {
	repo := buildInceptionRepo(t)
	_, err := runCommand(t, "release",
		"--repo", repo, "--to", "main",
		"--action", "recut",
		"--claimed-bump", "patch", "--blast", "low",
		"--verify-time", releaseEpoch, "--dry-run", "--json")
	if err == nil || !strings.Contains(err.Error(), "recut requires --bootstrap-descriptor") {
		t.Errorf("recut without a descriptor: error = %v, want a --bootstrap-descriptor requirement", err)
	}
}
