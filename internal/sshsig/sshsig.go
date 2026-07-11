// SPDX-License-Identifier: Apache-2.0

package sshsig

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Package sshsig implements OpenSSH's detached-signature format (PROTOCOL.sshsig),
// the format git produces for gpg.format=ssh commit signing. Verification is
// pure computation over the commit payload and the embedded public key;
// which keys are trusted is the allowed-signers registry's business
// (allowedsigners.go), injected by the caller (ADR-018).

const (
	sshSigPEMType = "SSH SIGNATURE"
	sshSigMagic   = "SSHSIG"
)

// Signature is a parsed SSH signature.
type Signature struct {
	PublicKey ssh.PublicKey
	Namespace string
	hashAlg   string
	signature *ssh.Signature
}

// sshSigBlob is the SSHSIG wire layout after the 6-byte magic preamble.
type sshSigBlob struct {
	Version       uint32
	PublicKey     []byte
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     []byte
}

// Parse decodes the PEM-armored SSHSIG blob.
func Parse(armored string) (*Signature, error) {
	block, _ := pem.Decode([]byte(armored))
	if block == nil || block.Type != sshSigPEMType {
		return nil, fmt.Errorf("sshsig: not an SSH SIGNATURE block")
	}
	if len(block.Bytes) < len(sshSigMagic) || string(block.Bytes[:len(sshSigMagic)]) != sshSigMagic {
		return nil, fmt.Errorf("sshsig: missing SSHSIG magic preamble")
	}

	var blob sshSigBlob
	if err := ssh.Unmarshal(block.Bytes[len(sshSigMagic):], &blob); err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	if blob.Version != 1 {
		return nil, fmt.Errorf("sshsig: unsupported version %d", blob.Version)
	}

	key, err := ssh.ParsePublicKey(blob.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sshsig: embedded public key: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(blob.Signature, &sig); err != nil {
		return nil, fmt.Errorf("sshsig: signature: %w", err)
	}
	return &Signature{
		PublicKey: key,
		Namespace: blob.Namespace,
		hashAlg:   blob.HashAlgorithm,
		signature: &sig,
	}, nil
}

// Verify checks the signature over message. The signed data is the SSHSIG
// preamble binding the namespace, hash algorithm, and message digest —
// signing covers H(message), never the raw message.
func (s *Signature) Verify(message []byte) error {
	var digest []byte
	switch s.hashAlg {
	case "sha256":
		sum := sha256.Sum256(message)
		digest = sum[:]
	case "sha512":
		sum := sha512.Sum512(message)
		digest = sum[:]
	default:
		return fmt.Errorf("sshsig: unsupported hash algorithm %q", s.hashAlg)
	}

	signed := append([]byte(sshSigMagic), ssh.Marshal(struct {
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Digest        []byte
	}{s.Namespace, "", s.hashAlg, digest})...)

	return s.PublicKey.Verify(signed, s.signature)
}

// IsSSHSignature reports whether an armored signature block is SSHSIG;
// IsPGPSignature the OpenPGP family. Anything else is an unknown family —
// and every family this verifier cannot verify is unverifiable, never
// skipped (the fail-closed key-family seam; fixture plan §2.1).
func IsSSHSignature(armored string) bool {
	return strings.Contains(armored, "-----BEGIN "+sshSigPEMType+"-----")
}

func IsPGPSignature(armored string) bool {
	return strings.Contains(armored, "-----BEGIN PGP SIGNATURE-----")
}
