// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/pgp/pgptest"
)

// The §9 identity vocabulary lets a policy name its own trust-material paths:
// [identity.human] gpg_keyring and [identity] attestation_signers. When the
// corresponding CLI flag is absent, the verifier defaults from these fields,
// reading the file from TO's tree — the same mechanism that already resolves
// identity.human.allowed_signers (§10 step 1). An explicit flag overrides.
// These tests prove the two new resolvers and the precedence, at both the
// resolver seam and the whole §10 pipeline.

// repoWithTreeFiles builds a one-commit git repository whose tree contains the
// given files (path -> content). The commit is unsigned: these fixtures test
// tree reads (readTreeFile), which never inspect the signature.
func repoWithTreeFiles(t *testing.T, files map[string]string) (repoPath, rev string) {
	t.Helper()
	dir := t.TempDir()
	r, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := r.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add(name); err != nil {
			t.Fatalf("Add %s: %v", name, err)
		}
	}
	h, err := wt.Commit("fixture tree", &git.CommitOptions{
		Author: &object.Signature{Name: "fixture", Email: "fixture@semver-trust.test", When: pinnedEpoch},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return dir, h.String()
}

// TestResolvePGPKeyringFromTree covers the [identity.human] gpg_keyring
// default: the keyring resolves from TO's tree when --gpg-keyring is absent, a
// supplied flag overrides the policy, neither source yields a nil keyring (GPG
// family stays fail-closed), and a policy-declared path missing from the tree
// is a fail-closed error.
func TestResolvePGPKeyringFromTree(t *testing.T) {
	signer, err := pgptest.NewSigner("Tree Signer", "tree@semver-trust.test", pinnedEpoch, 0)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	armored, err := pgptest.ArmoredKeyring(signer)
	if err != nil {
		t.Fatalf("ArmoredKeyring: %v", err)
	}
	repo, rev := repoWithTreeFiles(t, map[string]string{
		".semver-trust/gpg-keyring.asc": string(armored),
	})

	// No flag: keyring resolved from the policy-declared in-tree path (§9).
	pol := minimalPolicy(t)
	pol.Identity.Human.GPGKeyring = ".semver-trust/gpg-keyring.asc"
	kr, err := resolvePGPKeyring(Options{RepoPath: repo, To: rev}, pol, repo)
	if err != nil {
		t.Fatalf("resolve from tree: %v", err)
	}
	if kr == nil {
		t.Fatal("keyring nil; want the in-tree keyring resolved")
	}

	// Flag overrides policy: an explicit --gpg-keyring wins even when the
	// policy names a (here bogus) tree path that would error if consulted.
	onDisk := filepath.Join(t.TempDir(), "kr.asc")
	if err := os.WriteFile(onDisk, armored, 0o600); err != nil {
		t.Fatal(err)
	}
	polBogusTree := minimalPolicy(t)
	polBogusTree.Identity.Human.GPGKeyring = ".semver-trust/does-not-exist.asc"
	kr, err = resolvePGPKeyring(Options{RepoPath: repo, To: rev, GPGKeyringPath: onDisk}, polBogusTree, repo)
	if err != nil {
		t.Fatalf("flag override: %v", err)
	}
	if kr == nil {
		t.Fatal("keyring nil under flag override")
	}

	// Neither source: nil keyring, GPG family stays fail-closed unsupported.
	kr, err = resolvePGPKeyring(Options{RepoPath: repo, To: rev}, minimalPolicy(t), repo)
	if err != nil {
		t.Fatalf("no source: %v", err)
	}
	if kr != nil {
		t.Fatal("keyring non-nil when neither flag nor policy names one")
	}

	// A policy-declared path absent from the tree is a fail-closed error, not
	// an empty keyring: unreadable trust material aborts, never degrades.
	polMissing := minimalPolicy(t)
	polMissing.Identity.Human.GPGKeyring = ".semver-trust/absent.asc"
	if _, err := resolvePGPKeyring(Options{RepoPath: repo, To: rev}, polMissing, repo); err == nil {
		t.Fatal("missing in-tree keyring did not error")
	}
}

// TestBuildAttestationVerifierFromTree covers the [identity] attestation_signers
// default: the registry resolves from TO's tree when --attestation-signers is
// absent, a supplied flag overrides the policy, and neither source yields a nil
// verifier (reviews then classify none, §4.3).
func TestBuildAttestationVerifierFromTree(t *testing.T) {
	enrollment := bobEnrollmentLine(t)
	repo, rev := repoWithTreeFiles(t, map[string]string{
		".semver-trust/attestation_signers": enrollment,
	})

	pol := minimalPolicy(t)
	pol.Identity.AttestationSigners = ".semver-trust/attestation_signers"
	v, err := buildAttestationVerifier(Options{RepoPath: repo, To: rev}, pol, repo)
	if err != nil {
		t.Fatalf("resolve from tree: %v", err)
	}
	if v == nil {
		t.Fatal("verifier nil; want the in-tree registry resolved")
	}

	// Flag overrides policy.
	onDisk := filepath.Join(t.TempDir(), "attestation_signers")
	if err := os.WriteFile(onDisk, []byte(enrollment), 0o644); err != nil {
		t.Fatal(err)
	}
	polBogusTree := minimalPolicy(t)
	polBogusTree.Identity.AttestationSigners = ".semver-trust/absent"
	v, err = buildAttestationVerifier(Options{RepoPath: repo, To: rev, AttestationSignersPath: onDisk}, polBogusTree, repo)
	if err != nil {
		t.Fatalf("flag override: %v", err)
	}
	if v == nil {
		t.Fatal("verifier nil under flag override")
	}

	// Neither source: nil verifier (reviews classify none).
	v, err = buildAttestationVerifier(Options{RepoPath: repo, To: rev}, minimalPolicy(t), repo)
	if err != nil {
		t.Fatalf("no source: %v", err)
	}
	if v != nil {
		t.Fatal("verifier non-nil when neither flag nor policy names a registry")
	}
}

// TestVerifyDefaultsTrustMaterialFromTree is the §10 end-to-end proof: a repo
// whose policy declares BOTH identity.human.allowed_signers and (the new)
// identity.attestation_signers as in-tree paths verifies flag-free. Bob's
// stored review lifts alice's commit to T3 — which is only reachable if the
// attestation registry was resolved, and with no --attestation-signers flag
// the sole source is the tree. Supplying a flag that enrolls a different
// signer overrides the tree and aborts, proving precedence at the pipeline.
func TestVerifyDefaultsTrustMaterialFromTree(t *testing.T) {
	policyTOML := `# fixture-local test policy (§9 identity vocabulary)
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T0"

[identity]
attestation_signers = ".semver-trust/attestation_signers"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"
`
	allowedSigners, err := os.ReadFile(allowedSignersPath(t))
	if err != nil {
		t.Fatal(err)
	}
	repo, sha := sshSignedRepoWithTree(t, map[string]string{
		".semver-trust/policy.toml":         policyTOML,
		".semver-trust/allowed_signers":     string(allowedSigners),
		".semver-trust/attestation_signers": bobEnrollmentLine(t),
		"app.txt":                           "v1\n",
	}, "alice@semver-trust.test", "human-alice", "feat: initial release\n\nProvenance: human")

	opts := Options{
		RepoPath:   repo,
		From:       "",
		To:         sha,
		PolicyPath: ".semver-trust/policy.toml",
		VerifyTime: pinnedEpoch,
	}

	// Before any review: flag-free verify succeeds, allowed_signers defaulted
	// from the tree, alice classified human/none at T2.
	before, err := Verify(opts)
	if err != nil {
		t.Fatalf("pre-review verify: %v", err)
	}
	if len(before.Commits) != 1 {
		t.Fatalf("commits = %d, want 1", len(before.Commits))
	}
	assertCommit(t, before.Commits[0], "T2", "human", "none")

	// Bob reviews the commit post hoc; the attestation lands in the repo.
	emission := emitBobReview(t, []string{sha})
	if _, err := attest.StoreForSubjects(attest.GitRefStore{Path: repo}, []string{sha}, emission.Envelope); err != nil {
		t.Fatalf("storing review: %v", err)
	}

	// Flag-free again: with --attestation-signers absent, the verifier defaults
	// the registry from [identity] attestation_signers in TO's tree, verifies
	// bob's review, and lifts alice author + bob reviewer to T3 (two distinct
	// accountable humans, §3.2). This lift is the tree default's fingerprint.
	after, err := Verify(opts)
	if err != nil {
		t.Fatalf("post-review flag-free verify: %v", err)
	}
	assertCommit(t, after.Commits[0], "T3", "human", "human_distinct")

	// Flag overrides the tree: an explicit registry enrolling only ci-bot makes
	// bob an unknown attestation signer, and the stored review aborts (§8.2).
	override := Options{
		RepoPath:               repo,
		From:                   "",
		To:                     sha,
		PolicyPath:             ".semver-trust/policy.toml",
		AttestationSignersPath: filepath.Join(cryptoVendorDir(t), "attestations", "allowed_signers"),
		VerifyTime:             pinnedEpoch,
	}
	_, err = Verify(override)
	assertAbortStep(t, err, stepAttestation)
}

// bobEnrollmentLine is bob's vendored public key enrolled for the attestation
// namespace (ADR-022) — the content an in-tree attestation_signers registry
// carries.
func bobEnrollmentLine(t *testing.T) string {
	t.Helper()
	pub, err := os.ReadFile(filepath.Join(cryptoVendorDir(t), "keys", "human-bob.pub"))
	if err != nil {
		t.Fatal(err)
	}
	return "bob@semver-trust.test namespaces=\"" + attest.Namespace + "\" " + strings.TrimSpace(string(pub)) + "\n"
}

// sshSignedRepoWithTree builds a one-commit repository whose tree carries the
// given files and whose commit is SSH-signed by the named vendored key at the
// pinned epoch — the git-CLI construction the vendored fixture builder uses,
// scoped to a single hermetic commit (no network, local key material only).
func sshSignedRepoWithTree(t *testing.T, files map[string]string, signerEmail, keyName, message string) (repo, sha string) {
	t.Helper()
	repo = t.TempDir()
	git := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_DATE=2026-01-01T00:00:00 +0000",
			"GIT_COMMITTER_DATE=2026-01-01T00:00:00 +0000")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return out
	}
	git("-c", "init.defaultBranch=main", "init", "--quiet", "--object-format=sha1")
	for name, content := range files {
		full := filepath.Join(repo, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		git("add", name)
	}

	// ssh-keygen refuses a group/world-readable private key: stage a 0600 copy
	// (with its .pub) in a private dir, exactly as the fixture builder does.
	keyDir := t.TempDir()
	for _, suffix := range []string{"", ".pub"} {
		src := filepath.Join(cryptoVendorDir(t), "keys", keyName+suffix)
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o600)
		if suffix == ".pub" {
			mode = 0o644
		}
		if err := os.WriteFile(filepath.Join(keyDir, keyName+suffix), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	keyPath := filepath.Join(keyDir, keyName)

	git("-c", "user.name="+signerEmail, "-c", "user.email="+signerEmail,
		"-c", "gpg.format=ssh", "-c", "user.signingkey="+keyPath,
		"-c", "commit.gpgsign=true", "commit", "--quiet", "-m", message)
	sha = strings.TrimSpace(string(git("rev-parse", "HEAD")))
	return repo, sha
}
