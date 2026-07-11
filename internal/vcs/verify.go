// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/pgp"
	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

// gitSSHNamespace is the signature namespace git uses for commits and tags;
// a signature bound to any other purpose does not cover a commit.
const gitSSHNamespace = "git"

// AllowedSigner re-exports the registry entry type consumed by
// VerifyCommitSignature; parsing and resolution live in internal/sshsig,
// shared with attestation verification.
type AllowedSigner = sshsig.AllowedSigner

// ParseAllowedSigners re-exports the registry parser.
func ParseAllowedSigners(data []byte) ([]AllowedSigner, error) {
	return sshsig.ParseAllowedSigners(data)
}

// PGPKeyring re-exports the OpenPGP public-keyring type consumed by
// VerifyCommitSignature; parsing and verification live in internal/pgp.
type PGPKeyring = pgp.Keyring

// ParsePGPKeyring re-exports the OpenPGP keyring parser.
func ParsePGPKeyring(data []byte) (*PGPKeyring, error) {
	return pgp.ParseKeyring(data)
}

// TrustedSigners bundles the injected trust material for commit-signature
// verification, one field per key family (§4.2, ADR-018: all trust material
// is injected, never ambient). Each family verifies only against its own
// material; a family with no material injected fails closed as unsupported.
type TrustedSigners struct {
	// AllowedSigners is the SSH allowed-signers registry (§9
	// identity.human.allowed_signers).
	AllowedSigners []AllowedSigner
	// PGPKeyring is the OpenPGP public keyring; nil means the GPG family is
	// not verifiable in this run and a PGP-signed commit aborts with
	// ErrUnsupportedKeyFamily — the fixture plan §2.1 fail-closed rider,
	// unchanged from the SSH-only verifier.
	PGPKeyring *PGPKeyring
}

// Signature-verification failure classes (§5.2, §10 step 3). Every one is an
// abort: a commit that cannot be verified end-to-end has no level —
// unverifiable is not T0.
var (
	// ErrUnsigned — the commit carries no signature at all (§4.2: every
	// commit on a protected branch MUST be signed).
	ErrUnsigned = errors.New("commit is unsigned")
	// ErrUnsupportedKeyFamily — the signature belongs to a key family this
	// verifier cannot verify (e.g. OpenPGP under the SSH-only v1). A family
	// the verifier cannot verify is unverifiable, never skipped (fixture
	// plan §2.1 fail-closed rider).
	ErrUnsupportedKeyFamily = errors.New("unsupported signature key family")
	// ErrUnknownSigner — the signing key is absent from the injected
	// allowed-signers registry (alias of the shared sshsig sentinel).
	ErrUnknownSigner = sshsig.ErrUnknownSigner
	// ErrRevokedSigner — the signing key is enrolled but not valid at the
	// verification instant: distinct from never-enrolled (alias of the
	// shared sshsig sentinel).
	ErrRevokedSigner = sshsig.ErrRevokedSigner
	// ErrInvalidSignature — the signature does not verify over the commit
	// bytes (tampering, corruption, or a signature for other content).
	ErrInvalidSignature = errors.New("signature does not verify")
)

// VerifiedSignature is a successful verification: the enrolled principal the
// key resolves to and the key's fingerprint. Mapping the principal to an
// identity class (§4.2 human/agent) is the identity map's job (§9), layered
// above this.
type VerifiedSignature struct {
	Principal   string
	Fingerprint string
}

// VerifyCommitSignature verifies the signature of the commit at rev in the
// repository at path against the injected trust material, at the injected
// verification instant (ADR-018: no ambient trust material, no wall clock).
// The signature's key family selects the verifier: SSH armor against the
// allowed-signers registry, PGP armor against the OpenPGP keyring when one
// is injected. It fails closed on every path: unsigned, unsupported key
// family (including PGP with no keyring injected), unknown or revoked
// signer, wrong namespace, or a signature that does not cover the commit
// bytes.
func VerifyCommitSignature(path, rev string, trusted TrustedSigners, at time.Time) (VerifiedSignature, error) {
	apath, err := rootPath(path)
	if err != nil {
		return VerifiedSignature{}, err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return VerifiedSignature{}, err
	}
	commit, err := resolveCommit(r, rev)
	if err != nil {
		return VerifiedSignature{}, fmt.Errorf("verify: resolving %q: %w", rev, err)
	}

	switch {
	case commit.PGPSignature == "":
		return VerifiedSignature{}, fmt.Errorf("verify %s: %w", commit.Hash, ErrUnsigned)
	case sshsig.IsPGPSignature(commit.PGPSignature):
		return verifyPGPCommit(commit, trusted.PGPKeyring, at)
	case !sshsig.IsSSHSignature(commit.PGPSignature):
		return VerifiedSignature{}, fmt.Errorf("verify %s: %w", commit.Hash, ErrUnsupportedKeyFamily)
	}

	sig, err := sshsig.Parse(commit.PGPSignature)
	if err != nil {
		return VerifiedSignature{}, fmt.Errorf("verify %s: %w: %v", commit.Hash, ErrInvalidSignature, err)
	}
	if sig.Namespace != gitSSHNamespace {
		return VerifiedSignature{}, fmt.Errorf(
			"verify %s: signature namespace %q is not %q: %w",
			commit.Hash, sig.Namespace, gitSSHNamespace, ErrInvalidSignature,
		)
	}

	// Resolve the embedded key against the injected registry before any
	// cryptography: an unenrolled key's mathematically valid signature is
	// still an abort, and enrolled-but-invalid is reported distinctly.
	principal, err := sshsig.Resolve(sig.PublicKey, trusted.AllowedSigners, gitSSHNamespace, at)
	if err != nil {
		return VerifiedSignature{}, fmt.Errorf("verify %s: %w", commit.Hash, err)
	}

	payload, err := commitPayload(commit)
	if err != nil {
		return VerifiedSignature{}, err
	}
	if err := sig.Verify(payload); err != nil {
		return VerifiedSignature{}, fmt.Errorf("verify %s: %w: %v", commit.Hash, ErrInvalidSignature, err)
	}

	return VerifiedSignature{
		Principal:   principal,
		Fingerprint: ssh.FingerprintSHA256(sig.PublicKey),
	}, nil
}

// verifyPGPCommit is the OpenPGP arm of the key-family dispatch. With no
// keyring injected the family is unverifiable and fails closed — the
// conformance contract's fail-closed rider (fixture plan §2.1), unchanged.
// With one, internal/pgp verifies the detached signature over the commit
// bytes and its unknown/invalid-at-instant/bad-signature failures map onto
// the existing sentinels, so errors.Is identities stay uniform across key
// families.
func verifyPGPCommit(commit *object.Commit, keyring *PGPKeyring, at time.Time) (VerifiedSignature, error) {
	if keyring == nil {
		return VerifiedSignature{}, fmt.Errorf(
			"verify %s: OpenPGP: no OpenPGP keyring injected: %w", commit.Hash, ErrUnsupportedKeyFamily)
	}
	payload, err := commitPayload(commit)
	if err != nil {
		return VerifiedSignature{}, err
	}
	verified, err := pgp.Verify(payload, commit.PGPSignature, keyring, at)
	switch {
	case err == nil:
	case errors.Is(err, pgp.ErrUnknownKey):
		return VerifiedSignature{}, fmt.Errorf("verify %s: OpenPGP: %w", commit.Hash, ErrUnknownSigner)
	case errors.Is(err, pgp.ErrKeyInvalidAtInstant):
		return VerifiedSignature{}, fmt.Errorf("verify %s: OpenPGP: %w: %v", commit.Hash, ErrRevokedSigner, err)
	default:
		return VerifiedSignature{}, fmt.Errorf("verify %s: OpenPGP: %w: %v", commit.Hash, ErrInvalidSignature, err)
	}
	return VerifiedSignature{
		Principal:   verified.Principal,
		Fingerprint: verified.Fingerprint,
	}, nil
}

// commitPayload returns the bytes the signature covers: the commit object
// encoded without its signature header.
func commitPayload(c *object.Commit) ([]byte, error) {
	obj := memory.NewStorage().NewEncodedObject()
	if err := c.EncodeWithoutSignature(obj); err != nil {
		return nil, err
	}
	reader, err := obj.Reader()
	if err != nil {
		return nil, err
	}
	payload, err := io.ReadAll(reader)
	if closeErr := reader.Close(); err == nil {
		err = closeErr
	}
	return payload, err
}
