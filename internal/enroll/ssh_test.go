// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

func genPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

func lineFor(t *testing.T, principal, ns string, pub ssh.PublicKey) string {
	t.Helper()
	line, err := sshsig.FormatEnrollmentLine(principal, ns, pub)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func TestBuildSSHFormatsAndSelfChecks(t *testing.T) {
	pub := genPub(t)
	r, err := BuildSSH(pub, "alex@example.com", "git", nil, nil, time.Now())
	if err != nil {
		t.Fatalf("BuildSSH: %v", err)
	}
	if r.Line != lineFor(t, "alex@example.com", "git", pub) {
		t.Errorf("Line = %q, want the byte-exact FormatEnrollmentLine output", r.Line)
	}
	if !strings.HasPrefix(r.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint = %q, want a SHA256 fingerprint", r.Fingerprint)
	}
	if r.Warn != "" {
		t.Errorf("Warn = %q, want empty for a first enrollment", r.Warn)
	}
	// The new content self-checks: it parses and resolves in the target namespace.
	signers, err := sshsig.ParseAllowedSigners(r.NewContent)
	if err != nil {
		t.Fatalf("resulting registry does not parse: %v", err)
	}
	if _, err := sshsig.Resolve(pub, signers, "git", time.Now()); err != nil {
		t.Errorf("resulting registry does not resolve the key: %v", err)
	}
}

func TestBuildSSHRefusesDuplicate(t *testing.T) {
	pub := genPub(t)
	existing := lineFor(t, "alex@example.com", "git", pub) + "\n"
	_, err := BuildSSH(pub, "alex@example.com", "git", []byte(existing), nil, time.Now())
	if err == nil || !strings.Contains(err.Error(), "already enrolled as alex@example.com") {
		t.Errorf("duplicate key error = %v, want 'already enrolled as alex@example.com'", err)
	}
}

func TestBuildSSHWarnsSameEmailDifferentKey(t *testing.T) {
	existing := lineFor(t, "alex@example.com", "git", genPub(t)) + "\n"
	newPub := genPub(t)
	r, err := BuildSSH(newPub, "alex@example.com", "git", []byte(existing), nil, time.Now())
	if err != nil {
		t.Fatalf("a second key for the same principal is legal: %v", err)
	}
	if r.Warn == "" {
		t.Error("want a WARN when the principal already has a different key")
	}
}

func TestBuildSSHRefusesCrossRegistry(t *testing.T) {
	pub := genPub(t)
	// The same key already enrolled in the OTHER registry (as an attestation key).
	cross := lineFor(t, "alex@example.com", "attestation@semver-trust.dev", pub) + "\n"
	_, err := BuildSSH(pub, "alex@example.com", "git", nil, []byte(cross), time.Now())
	if err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Errorf("cross-registry error = %v, want the ADR-040 distinctness refusal", err)
	}
}

func TestBuildSSHRefusesBrokenExisting(t *testing.T) {
	pub := genPub(t)
	_, err := BuildSSH(pub, "alex@example.com", "git", []byte("this is not a valid signer line\n"), nil, time.Now())
	if err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Errorf("broken existing registry error = %v, want a parse refusal", err)
	}
}
