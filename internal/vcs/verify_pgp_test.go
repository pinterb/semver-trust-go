// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/semver-trust/semver-trust-go/internal/pgp/pgptest"
)

// Full VerifyCommitSignature round-trips over real GPG-signed commits: the
// fixture repositories are built hermetically in-test (no network, no gpg
// binary) with per-run keys — the commit payload bytes are detached-signed
// with go-crypto and assembled into the raw commit object's gpgsig header,
// the same construction git performs. The cross-implementation
// vendored-GPG-fixture question is deferred to a future spec-repo round
// (fixture plan §2.1); these tests cover this implementation's GPG arm.

// pgpEpoch matches the crypto fixture plan §3 pinned instant.
var pgpEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const pgpCommitMessage = "feat: gpg change\n\nProvenance: human\n"

func pgpSigner(t *testing.T, email string, at time.Time, lifetimeSecs uint32) *openpgp.Entity {
	t.Helper()
	e, err := pgptest.NewSigner("Test Signer", email, at, lifetimeSecs)
	if err != nil {
		t.Fatalf("generating entity: %v", err)
	}
	return e
}

func pgpTrust(t *testing.T, entities ...*openpgp.Entity) TrustedSigners {
	t.Helper()
	armored, err := pgptest.ArmoredKeyring(entities...)
	if err != nil {
		t.Fatalf("armoring keyring: %v", err)
	}
	keyring, err := ParsePGPKeyring(armored)
	if err != nil {
		t.Fatalf("ParsePGPKeyring: %v", err)
	}
	return TrustedSigners{PGPKeyring: keyring}
}

func gpgSignedRepo(t *testing.T, signer *openpgp.Entity) (repo, sha string) {
	t.Helper()
	dir := t.TempDir()
	sha, err := pgptest.NewRepoWithSignedCommit(dir, signer, pgpEpoch, pgpCommitMessage)
	if err != nil {
		t.Fatalf("building GPG-signed fixture repo: %v", err)
	}
	return dir, sha
}

func TestVerifyGPGEnrolledKey(t *testing.T) {
	signer := pgpSigner(t, "gpg-signer@semver-trust.test", pgpEpoch, 0)
	repo, sha := gpgSignedRepo(t, signer)

	got, err := VerifyCommitSignature(repo, sha, pgpTrust(t, signer), pgpEpoch)
	if err != nil {
		t.Fatalf("VerifyCommitSignature: %v", err)
	}
	if got.Principal != "gpg-signer@semver-trust.test" {
		t.Errorf("principal = %q, want gpg-signer@semver-trust.test", got.Principal)
	}
	if got.Fingerprint == "" {
		t.Error("fingerprint is empty")
	}
}

func TestVerifyGPGUnknownKeyAborts(t *testing.T) {
	mallory := pgpSigner(t, "mallory@semver-trust.test", pgpEpoch, 0)
	enrolled := pgpSigner(t, "alice@semver-trust.test", pgpEpoch, 0)
	repo, sha := gpgSignedRepo(t, mallory)

	_, err := VerifyCommitSignature(repo, sha, pgpTrust(t, enrolled), pgpEpoch)
	if !errors.Is(err, ErrUnknownSigner) {
		t.Errorf("error = %v, want ErrUnknownSigner", err)
	}
}

// A key expired at the verification instant is the revoked-class abort,
// distinct from never-enrolled — same split as the SSH registry's
// valid-before window.
func TestVerifyGPGExpiredAtInstantAbortsAsRevoked(t *testing.T) {
	carol := pgpSigner(t, "carol@semver-trust.test", pgpEpoch, 3600)
	repo, sha := gpgSignedRepo(t, carol)

	_, err := VerifyCommitSignature(repo, sha, pgpTrust(t, carol), pgpEpoch.Add(2*time.Hour))
	if !errors.Is(err, ErrRevokedSigner) {
		t.Errorf("error = %v, want ErrRevokedSigner", err)
	}

	// Within the key's lifetime the same commit verifies: the abort above is
	// the instant's doing.
	if _, err := VerifyCommitSignature(repo, sha, pgpTrust(t, carol), pgpEpoch.Add(time.Minute)); err != nil {
		t.Errorf("VerifyCommitSignature within lifetime: %v", err)
	}
}

func TestVerifyGPGTamperedPayloadAborts(t *testing.T) {
	signer := pgpSigner(t, "alice@semver-trust.test", pgpEpoch, 0)
	dir := t.TempDir()
	sha, err := pgptest.NewRepoWithTamperedCommit(dir, signer, pgpEpoch, pgpCommitMessage)
	if err != nil {
		t.Fatalf("building tampered fixture repo: %v", err)
	}

	_, err = VerifyCommitSignature(dir, sha, pgpTrust(t, signer), pgpEpoch)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("error = %v, want ErrInvalidSignature", err)
	}
}

// With no keyring injected the GPG family stays fail-closed unsupported —
// the conformance contract's §2.1 rider — even for a commit that would
// verify with the right keyring, and the message says why.
func TestVerifyGPGNoKeyringFailsClosed(t *testing.T) {
	signer := pgpSigner(t, "alice@semver-trust.test", pgpEpoch, 0)
	repo, sha := gpgSignedRepo(t, signer)

	_, err := VerifyCommitSignature(repo, sha, TrustedSigners{}, pgpEpoch)
	if !errors.Is(err, ErrUnsupportedKeyFamily) {
		t.Fatalf("error = %v, want ErrUnsupportedKeyFamily", err)
	}
	if !strings.Contains(err.Error(), "no OpenPGP keyring injected") {
		t.Errorf("error %q does not say no OpenPGP keyring was injected", err)
	}
}
