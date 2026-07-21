// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

var signEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// aliceSigner loads the vendored human-alice test key. Signing happens in Go
// (ssh.ParsePrivateKey does not care about file modes), so no 0600 staging
// copy is needed.
func aliceSigner(t *testing.T) ssh.Signer {
	t.Helper()
	keyBytes, err := os.ReadFile(filepath.Join(cryptoVendorDir(t), "keys", "human-alice"))
	if err != nil {
		t.Fatalf("reading vendored test key: %v", err)
	}
	s, err := sshsig.LoadSigner(keyBytes)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	return s
}

// The tag-object assembly round trip (§10 step 9): CreateSignedTag writes an
// annotated tag whose embedded SSHSIG — in git's own "git" namespace —
// verifies over the encoded tag object minus the signature, through this
// module's verifier AND through git itself against the vendored
// allowed-signers registry.
func TestCreateSignedTagRoundTrip(t *testing.T) {
	repo, _ := buildFixtures(t)
	signer := aliceSigner(t)

	// Message deliberately lacks the trailing newline: the writer must
	// normalize it, or the message and signature would concatenate into a
	// corrupt object.
	err := CreateSignedTag(repo, "v9.9.9", "HEAD", "alice", "alice@semver-trust.test",
		"v9.9.9\n\nsemver-trust signed-tag round trip", signEpoch, signer)
	if err != nil {
		t.Fatalf("CreateSignedTag: %v", err)
	}

	r, err := git.PlainOpenWithOptions(repo, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := r.Reference(plumbing.NewTagReferenceName("v9.9.9"), true)
	if err != nil {
		t.Fatalf("tag ref: %v", err)
	}
	tag, err := r.TagObject(ref.Hash())
	if err != nil {
		t.Fatalf("tag object: %v", err)
	}

	head, err := r.Head()
	if err != nil {
		t.Fatal(err)
	}
	if tag.Target != head.Hash() {
		t.Errorf("tag target = %s, want HEAD %s", tag.Target, head.Hash())
	}
	if tag.Tagger.Name != "alice" || tag.Tagger.Email != "alice@semver-trust.test" {
		t.Errorf("tagger = %s <%s>", tag.Tagger.Name, tag.Tagger.Email)
	}
	if !tag.Tagger.When.Equal(signEpoch) {
		t.Errorf("tagger when = %v, want the injected %v (ADR-018)", tag.Tagger.When, signEpoch)
	}
	if !strings.HasSuffix(tag.Message, "\n") {
		t.Errorf("message not newline-terminated: %q", tag.Message)
	}

	// Our verifier accepts the embedded signature over the payload-minus-
	// signature bytes, in the git namespace, from alice's enrolled key.
	payloadObj := &plumbing.MemoryObject{}
	if err := tag.EncodeWithoutSignature(payloadObj); err != nil {
		t.Fatal(err)
	}
	payload, err := readEncoded(payloadObj)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Parse(tag.PGPSignature)
	if err != nil {
		t.Fatalf("embedded signature does not parse as SSHSIG: %v", err)
	}
	if sig.Namespace != GitSSHNamespace {
		t.Errorf("signature namespace = %q, want %q (git signs tags in the git namespace)", sig.Namespace, GitSSHNamespace)
	}
	if err := sig.Verify(payload); err != nil {
		t.Errorf("signature does not verify over the tag payload: %v", err)
	}
	registry, err := os.ReadFile(filepath.Join(cryptoVendorDir(t), "allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	signers, err := sshsig.ParseAllowedSigners(registry)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := sshsig.Resolve(sig.PublicKey, signers, GitSSHNamespace, signEpoch)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if principal != "alice@semver-trust.test" {
		t.Errorf("principal = %q, want alice", principal)
	}

	// git itself accepts the tag: `git tag -v` against the vendored registry
	// (hermetic — local repository, injected allowed-signers file).
	requireGitSSHVerify(t)
	cmd := exec.Command("git", "-C", repo,
		"-c", "gpg.ssh.allowedSignersFile="+filepath.Join(cryptoVendorDir(t), "allowed_signers"),
		"tag", "-v", "v9.9.9")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("git tag -v rejected the tag: %v\n%s", err, out)
	}
}

// A tag name already taken refuses with ErrTagExists — release tags are
// never overwritten; a re-cut is a new iteration (§7.2).
func TestCreateSignedTagRefusesExisting(t *testing.T) {
	repo, _ := buildFixtures(t)
	signer := aliceSigner(t)

	if exists, err := TagExists(repo, "v1.0.0"); err != nil || exists {
		t.Fatalf("TagExists before = %v, %v; want false, nil", exists, err)
	}
	if err := CreateSignedTag(repo, "v1.0.0", "HEAD", "alice", "alice@semver-trust.test",
		"v1.0.0", signEpoch, signer); err != nil {
		t.Fatalf("first CreateSignedTag: %v", err)
	}
	if exists, err := TagExists(repo, "v1.0.0"); err != nil || !exists {
		t.Fatalf("TagExists after = %v, %v; want true, nil", exists, err)
	}

	err := CreateSignedTag(repo, "v1.0.0", "HEAD", "alice", "alice@semver-trust.test",
		"v1.0.0 again", signEpoch, signer)
	if !errors.Is(err, ErrTagExists) {
		t.Fatalf("second CreateSignedTag = %v, want ErrTagExists", err)
	}
}

// DeleteTag is the release/v0.2 emit-path rollback (#76 M6): it removes a tag the
// arm created before signing, so a signing failure leaves no orphan tag. A
// present tag goes away; a missing tag deletes as a no-op (idempotent rollback).
func TestDeleteTag(t *testing.T) {
	repo, _ := buildFixtures(t)
	signer := aliceSigner(t)

	if err := CreateSignedTag(repo, "v2.0.0", "HEAD", "alice", "alice@semver-trust.test",
		"v2.0.0", signEpoch, signer); err != nil {
		t.Fatalf("CreateSignedTag: %v", err)
	}
	if exists, err := TagExists(repo, "v2.0.0"); err != nil || !exists {
		t.Fatalf("TagExists before delete = %v, %v; want true, nil", exists, err)
	}
	if err := DeleteTag(repo, "v2.0.0"); err != nil {
		t.Fatalf("DeleteTag: %v", err)
	}
	if exists, err := TagExists(repo, "v2.0.0"); err != nil || exists {
		t.Fatalf("TagExists after delete = %v, %v; want false, nil", exists, err)
	}
	// The ref-set no longer carries it (what the emit path re-reads).
	refs, err := TagRefs(repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := refs["v2.0.0"]; ok {
		t.Error("deleted tag still present in TagRefs")
	}
	// Idempotent: deleting an absent tag is not an error.
	if err := DeleteTag(repo, "v2.0.0"); err != nil {
		t.Errorf("DeleteTag on a missing tag = %v, want nil (no-op rollback)", err)
	}
}

// requireGitSSHVerify asserts the installed git can verify SSH signatures
// (>= 2.34, where gpg.ssh.allowedSignersFile arrived). CI runners have it;
// an older local git is a broken environment, not a skip.
func requireGitSSHVerify(t *testing.T) {
	t.Helper()
	out, err := exec.Command("git", "version").Output()
	if err != nil {
		t.Fatalf("git version: %v", err)
	}
	var major, minor int
	if _, err := fmt.Sscanf(string(out), "git version %d.%d", &major, &minor); err != nil {
		t.Fatalf("parsing %q: %v", out, err)
	}
	if major < 2 || (major == 2 && minor < 34) {
		t.Fatalf("git %d.%d cannot verify SSH signatures; >= 2.34 required", major, minor)
	}
}
