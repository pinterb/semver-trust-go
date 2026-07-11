// SPDX-License-Identifier: Apache-2.0

package sshsig

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Sign produces a PEM-armored SSHSIG (PROTOCOL.sshsig) over message in the
// given namespace: the signing side of Parse/Verify above, and the emission
// half of ADR-022. The signed data is the SSHSIG preamble binding the
// namespace, hash algorithm, and SHA-512 digest of message — signing covers
// H(message), never the raw message — so anything Sign emits round-trips
// through this package's verifier and through `ssh-keygen -Y verify`
// interchangeably (the cross-verification the conformance fixtures rely on).
//
// The namespace is required: PROTOCOL.sshsig makes it the purpose-binding
// field (ADR-022), and an empty one would produce a signature no compliant
// verifier accepts.
func Sign(signer ssh.Signer, namespace string, message []byte) (string, error) {
	if namespace == "" {
		return "", errors.New("sshsig: refusing to sign with an empty namespace (PROTOCOL.sshsig requires one)")
	}

	digest := sha512.Sum512(message)
	signedData := append([]byte(sshSigMagic), ssh.Marshal(struct {
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Digest        []byte
	}{namespace, "", "sha512", digest[:]})...)

	sig, err := signRaw(signer, signedData)
	if err != nil {
		return "", fmt.Errorf("sshsig: signing: %w", err)
	}

	blob := append([]byte(sshSigMagic), ssh.Marshal(sshSigBlob{
		Version:       1,
		PublicKey:     signer.PublicKey().Marshal(),
		Namespace:     namespace,
		Reserved:      "",
		HashAlgorithm: "sha512",
		Signature:     ssh.Marshal(*sig),
	})...)
	return string(pem.EncodeToMemory(&pem.Block{Type: sshSigPEMType, Bytes: blob})), nil
}

// signRaw signs the SSHSIG signed-data blob. RSA keys must sign with an
// rsa-sha2 algorithm: PROTOCOL.sshsig forbids the legacy ssh-rsa (SHA-1)
// form and ssh-keygen -Y verify rejects it, so a signer that can only
// produce it is an error, never a silent downgrade.
func signRaw(signer ssh.Signer, data []byte) (*ssh.Signature, error) {
	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("RSA signer cannot select an rsa-sha2 algorithm (PROTOCOL.sshsig forbids ssh-rsa/SHA-1)")
		}
		return as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
	}
	return signer.Sign(rand.Reader, data)
}

// LoadSigner parses an unencrypted OpenSSH private key into a signer.
// Passphrase-protected keys are out of scope for v1 and produce a clear
// error rather than a prompt (there is no terminal in the ADR-018-shaped
// call path to prompt on).
func LoadSigner(pemBytes []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		var passErr *ssh.PassphraseMissingError
		if errors.As(err, &passErr) {
			return nil, errors.New(
				"sshsig: private key is passphrase-protected, which is not supported; decrypt a copy first (ssh-keygen -p -N \"\")")
		}
		return nil, fmt.Errorf("sshsig: private key: %w", err)
	}
	return signer, nil
}
