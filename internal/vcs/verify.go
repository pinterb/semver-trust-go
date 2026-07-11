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
)

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
	// allowed-signers registry.
	ErrUnknownSigner = errors.New("signing key is not an allowed signer")
	// ErrRevokedSigner — the signing key is enrolled but not valid at the
	// verification instant (outside its valid-after/valid-before window):
	// distinct from never-enrolled.
	ErrRevokedSigner = errors.New("signing key enrollment is not valid at the verification time")
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

// VerifyCommitSignature verifies the SSH signature of the commit at rev in
// the repository at path against the injected allowed-signers registry, at
// the injected verification instant (ADR-018: no ambient trust material, no
// wall clock). It fails closed on every path: unsigned, unsupported key
// family, unknown or revoked signer, wrong namespace, or a signature that
// does not cover the commit bytes.
func VerifyCommitSignature(path, rev string, signers []AllowedSigner, at time.Time) (VerifiedSignature, error) {
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
	case isPGPSignature(commit.PGPSignature):
		return VerifiedSignature{}, fmt.Errorf("verify %s: OpenPGP: %w", commit.Hash, ErrUnsupportedKeyFamily)
	case !isSSHSignature(commit.PGPSignature):
		return VerifiedSignature{}, fmt.Errorf("verify %s: %w", commit.Hash, ErrUnsupportedKeyFamily)
	}

	sig, err := parseSSHSig(commit.PGPSignature)
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
	principal, err := resolveSigner(sig.PublicKey, signers, at)
	if err != nil {
		return VerifiedSignature{}, fmt.Errorf("verify %s: %w", commit.Hash, err)
	}

	payload, err := commitPayload(commit)
	if err != nil {
		return VerifiedSignature{}, err
	}
	if err := sig.verify(payload); err != nil {
		return VerifiedSignature{}, fmt.Errorf("verify %s: %w: %v", commit.Hash, ErrInvalidSignature, err)
	}

	return VerifiedSignature{
		Principal:   principal,
		Fingerprint: ssh.FingerprintSHA256(sig.PublicKey),
	}, nil
}

// resolveSigner finds the enrollment for a key and returns its principal.
// No enrollment at all is ErrUnknownSigner; enrollments that exist but are
// invalid at the verification instant (window, namespace, CA-only) are
// ErrRevokedSigner.
func resolveSigner(key ssh.PublicKey, signers []AllowedSigner, at time.Time) (string, error) {
	marshaled := string(key.Marshal())
	enrolled := false
	for _, s := range signers {
		if string(s.Key.Marshal()) != marshaled {
			continue
		}
		enrolled = true
		if s.CertAuthority || !s.forNamespace(gitSSHNamespace) || !s.validAt(at) {
			continue
		}
		return s.Principals[0], nil
	}
	if enrolled {
		return "", ErrRevokedSigner
	}
	return "", ErrUnknownSigner
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
