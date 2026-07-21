// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// Fingerprints enumerates every key's primary fingerprint (de-duped, keyring
// order) — the fingerprint-granular identity enroll diffs against.
func TestKeyringFingerprints(t *testing.T) {
	a := newSigner(t, "alex@example.com", epoch, 0)
	b := newSigner(t, "blake@example.com", epoch, 0)
	kr := keyring(t, a, b)

	fps := kr.Fingerprints()
	if len(fps) != 2 {
		t.Fatalf("Fingerprints() = %v, want 2 entries", fps)
	}
	// Each entry is exactly the identity Verify surfaces for that key.
	v, err := Verify([]byte("payload"), sign(t, a, []byte("payload"), epoch), kr, epoch)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	found := false
	for _, fp := range fps {
		if fp == v.Fingerprint {
			found = true
		}
	}
	if !found {
		t.Errorf("Verify fingerprint %q not in Fingerprints() %v", v.Fingerprint, fps)
	}
}

// A keyring must be public trust material: an armored private-key block is refused
// with the ErrPrivateKeyMaterial sentinel, so enroll can name the mistake precisely.
func TestParseKeyringRefusesPrivateKey(t *testing.T) {
	e := newSigner(t, "alex@example.com", epoch, 0)
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

	if _, err := ParseKeyring(buf.Bytes()); !errors.Is(err, ErrPrivateKeyMaterial) {
		t.Errorf("ParseKeyring(private) = %v, want ErrPrivateKeyMaterial", err)
	}
}
