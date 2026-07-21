// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/semver-trust/semver-trust-go/internal/pgp/pgptest"
)

var gpgEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func armoredPub(t *testing.T, email string) []byte {
	t.Helper()
	e, err := pgptest.NewSigner("Test Signer", email, gpgEpoch, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pgptest.ArmoredKeyring(e)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBuildGPGAppendsNewKey(t *testing.T) {
	cand := armoredPub(t, "alex@example.com")
	r, err := BuildGPG(cand, nil)
	if err != nil {
		t.Fatalf("BuildGPG: %v", err)
	}
	if len(r.NewFingerprints) != 1 {
		t.Errorf("NewFingerprints = %v, want 1", r.NewFingerprints)
	}
	if len(r.NewPrincipals) != 1 || r.NewPrincipals[0] != "alex@example.com" {
		t.Errorf("NewPrincipals = %v, want [alex@example.com]", r.NewPrincipals)
	}
	// The result is a valid keyring (self-check passed to get here).
	if !bytes.Contains(r.NewContent, []byte("PGP PUBLIC KEY BLOCK")) {
		t.Error("NewContent is not an armored public keyring")
	}
}

func TestBuildGPGAppendsToExisting(t *testing.T) {
	existing := armoredPub(t, "alex@example.com")
	cand := armoredPub(t, "blake@example.com")
	r, err := BuildGPG(cand, existing)
	if err != nil {
		t.Fatalf("BuildGPG: %v", err)
	}
	if len(r.NewFingerprints) != 1 {
		t.Errorf("NewFingerprints = %v, want just the new key", r.NewFingerprints)
	}
	if len(r.AllPrincipals) != 2 {
		t.Errorf("AllPrincipals = %v, want both keys after the append", r.AllPrincipals)
	}
}

func TestBuildGPGRefusesDuplicate(t *testing.T) {
	cand := armoredPub(t, "alex@example.com")
	// Enrolling the same key against a keyring that already contains it adds nothing.
	_, err := BuildGPG(cand, cand)
	if err == nil || !strings.Contains(err.Error(), "already enrolled") {
		t.Errorf("duplicate = %v, want a 'nothing to add' refusal", err)
	}
}

func TestBuildGPGRefusesPrivateKey(t *testing.T) {
	e, err := pgptest.NewSigner("Test Signer", "alex@example.com", gpgEpoch, 0)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := BuildGPG(buf.Bytes(), nil); err == nil || !strings.Contains(err.Error(), "private key material") {
		t.Errorf("private key input = %v, want a loud private-key refusal", err)
	}
}
