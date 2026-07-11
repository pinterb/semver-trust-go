// SPDX-License-Identifier: Apache-2.0

package sshsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}

// Sign → Parse → Verify must round-trip through this package's own verifier:
// the emission and verification halves are two views of one format.
func TestSignRoundTrip(t *testing.T) {
	signer := newTestSigner(t)
	message := []byte("DSSEv1 4 test 5 bytes")

	armored, err := Sign(signer, "attestation@semver-trust.dev", message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !IsSSHSignature(armored) {
		t.Fatalf("Sign output is not an SSH SIGNATURE block:\n%s", armored)
	}

	sig, err := Parse(armored)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if sig.Namespace != "attestation@semver-trust.dev" {
		t.Errorf("namespace = %q, want attestation@semver-trust.dev", sig.Namespace)
	}
	if err := sig.Verify(message); err != nil {
		t.Errorf("Verify: %v", err)
	}

	// A tampered message must not verify.
	if err := sig.Verify([]byte("DSSEv1 4 test 5 bytez")); err == nil {
		t.Error("tampered message verified")
	}
}

// An empty namespace is refused outright: PROTOCOL.sshsig requires one, and
// ADR-022's purpose binding depends on it.
func TestSignEmptyNamespaceRefused(t *testing.T) {
	if _, err := Sign(newTestSigner(t), "", []byte("m")); err == nil {
		t.Fatal("Sign with empty namespace succeeded")
	}
}

// vendoredKeyPath locates a test-only key from the ADR-021 vendored fixtures.
func vendoredKeyPath(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "vendor", "crypto", "keys", name)
}

// Signatures produced here must be accepted by OpenSSH itself, not just by
// our verifier: `ssh-keygen -Y verify` against an allowed_signers file is
// the interoperability contract ADR-022 leans on (deterministic, independently
// cross-verifiable fixtures). Wrong-namespace and tampered-message checks run
// through the same external verifier.
func TestSignVerifiesWithSSHKeygen(t *testing.T) {
	keyBytes, err := os.ReadFile(vendoredKeyPath(t, "human-bob"))
	if err != nil {
		t.Fatalf("reading vendored test key: %v", err)
	}
	signer, err := LoadSigner(keyBytes)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}

	const namespace = "attestation@semver-trust.dev"
	message := []byte("interop message for ssh-keygen cross-verification\n")
	armored, err := Sign(signer, namespace, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Our own verifier accepts it...
	sig, err := Parse(armored)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := sig.Verify(message); err != nil {
		t.Fatalf("our verifier rejected our signature: %v", err)
	}

	// ...and so must ssh-keygen, against a temp allowed_signers enrolling
	// bob's public key for the namespace.
	dir := t.TempDir()
	sigPath := filepath.Join(dir, "message.sig")
	if err := os.WriteFile(sigPath, []byte(armored), 0o644); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(vendoredKeyPath(t, "human-bob.pub"))
	if err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(dir, "allowed_signers")
	line := "bob@semver-trust.test namespaces=\"" + namespace + "\" " + strings.TrimSpace(string(pub)) + "\n"
	if err := os.WriteFile(allowed, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	verify := func(msg []byte, ns string) error {
		cmd := exec.Command("ssh-keygen", "-Y", "verify",
			"-f", allowed, "-I", "bob@semver-trust.test", "-n", ns, "-s", sigPath)
		cmd.Stdin = strings.NewReader(string(msg))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return &sshKeygenError{output: string(out), err: err}
		}
		return nil
	}

	if err := verify(message, namespace); err != nil {
		t.Errorf("ssh-keygen -Y verify rejected our signature: %v", err)
	}
	if err := verify(message, "git"); err == nil {
		t.Error("ssh-keygen accepted the signature in the wrong namespace")
	}
	if err := verify([]byte("tampered\n"), namespace); err == nil {
		t.Error("ssh-keygen accepted the signature over a tampered message")
	}
}

type sshKeygenError struct {
	output string
	err    error
}

func (e *sshKeygenError) Error() string { return e.err.Error() + ": " + e.output }

// A passphrase-protected key is out of scope for v1: the error must say so
// clearly instead of surfacing a bare parse failure or prompting.
func TestLoadSignerPassphraseProtected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("hunter2"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	_, err = LoadSigner(pem.EncodeToMemory(block))
	if err == nil {
		t.Fatal("LoadSigner accepted a passphrase-protected key")
	}
	if !strings.Contains(err.Error(), "passphrase-protected") {
		t.Errorf("error %q does not name the passphrase problem", err)
	}
}

func TestLoadSignerGarbage(t *testing.T) {
	if _, err := LoadSigner([]byte("not a key")); err == nil {
		t.Fatal("LoadSigner accepted garbage")
	}
}
