// SPDX-License-Identifier: Apache-2.0

package pgp

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/semver-trust/semver-trust-go/internal/pgp/pgptest"
)

// The pinned test epoch, matching the crypto fixture plan §3 instant.
var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newSigner(t *testing.T, email string, at time.Time, lifetimeSecs uint32) *openpgp.Entity {
	t.Helper()
	e, err := pgptest.NewSigner("Test Signer", email, at, lifetimeSecs)
	if err != nil {
		t.Fatalf("generating entity: %v", err)
	}
	return e
}

func keyring(t *testing.T, entities ...*openpgp.Entity) *Keyring {
	t.Helper()
	armored, err := pgptest.ArmoredKeyring(entities...)
	if err != nil {
		t.Fatalf("armoring keyring: %v", err)
	}
	kr, err := ParseKeyring(armored)
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}
	return kr
}

func sign(t *testing.T, signer *openpgp.Entity, payload []byte, at time.Time) string {
	t.Helper()
	config := &packet.Config{Time: func() time.Time { return at }}
	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&buf, signer, bytes.NewReader(payload), config); err != nil {
		t.Fatalf("signing: %v", err)
	}
	return buf.String()
}

func TestVerifyEnrolledKey(t *testing.T) {
	signer := newSigner(t, "alice@semver-trust.test", epoch, 0)
	payload := []byte("tree deadbeef\nauthor a <a@x> 0 +0000\n\nfeat: change\n")
	sig := sign(t, signer, payload, epoch)

	got, err := Verify(payload, sig, keyring(t, signer), epoch)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Principal != "alice@semver-trust.test" {
		t.Errorf("principal = %q, want alice@semver-trust.test", got.Principal)
	}
	if got.Fingerprint == "" {
		t.Error("fingerprint is empty")
	}
}

// A keyring with several keys resolves the actual signer, not the first key.
func TestVerifyResolvesSignerAmongMany(t *testing.T) {
	alice := newSigner(t, "alice@semver-trust.test", epoch, 0)
	bob := newSigner(t, "bob@semver-trust.test", epoch, 0)
	payload := []byte("payload\n")
	sig := sign(t, bob, payload, epoch)

	got, err := Verify(payload, sig, keyring(t, alice, bob), epoch)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Principal != "bob@semver-trust.test" {
		t.Errorf("principal = %q, want bob@semver-trust.test", got.Principal)
	}
}

func TestVerifyUnknownKeyAborts(t *testing.T) {
	mallory := newSigner(t, "mallory@semver-trust.test", epoch, 0)
	enrolled := newSigner(t, "alice@semver-trust.test", epoch, 0)
	payload := []byte("payload\n")
	sig := sign(t, mallory, payload, epoch)

	_, err := Verify(payload, sig, keyring(t, enrolled), epoch)
	if !errors.Is(err, ErrUnknownKey) {
		t.Errorf("error = %v, want ErrUnknownKey", err)
	}
}

// A key expired at the verification instant is enrolled-but-invalid: the
// revoked-class failure, distinct from never-enrolled. The one-hour lifetime
// is evaluated at the injected instant, never the wall clock (ADR-018).
func TestVerifyExpiredAtInstantAborts(t *testing.T) {
	carol := newSigner(t, "carol@semver-trust.test", epoch, 3600)
	payload := []byte("payload\n")
	sig := sign(t, carol, payload, epoch)

	_, err := Verify(payload, sig, keyring(t, carol), epoch.Add(2*time.Hour))
	if !errors.Is(err, ErrKeyInvalidAtInstant) {
		t.Errorf("error = %v, want ErrKeyInvalidAtInstant", err)
	}

	// The same material verifies within the key's lifetime: the failure above
	// is the instant's doing, not the fixture's.
	if _, err := Verify(payload, sig, keyring(t, carol), epoch.Add(time.Minute)); err != nil {
		t.Errorf("Verify within lifetime: %v", err)
	}
}

// A key created after the verification instant did not exist then: invalid
// material at that instant, the same revoked-class failure as expiry.
func TestVerifyKeyCreatedAfterInstantAborts(t *testing.T) {
	future := newSigner(t, "future@semver-trust.test", epoch.Add(24*time.Hour), 0)
	payload := []byte("payload\n")
	sig := sign(t, future, payload, epoch.Add(24*time.Hour))

	_, err := Verify(payload, sig, keyring(t, future), epoch)
	if !errors.Is(err, ErrKeyInvalidAtInstant) {
		t.Errorf("error = %v, want ErrKeyInvalidAtInstant", err)
	}
}

func TestVerifyTamperedPayloadAborts(t *testing.T) {
	signer := newSigner(t, "alice@semver-trust.test", epoch, 0)
	payload := []byte("payload\n")
	sig := sign(t, signer, payload, epoch)

	_, err := Verify([]byte("tampered payload\n"), sig, keyring(t, signer), epoch)
	if !errors.Is(err, ErrBadSignature) {
		t.Errorf("error = %v, want ErrBadSignature", err)
	}
}

func TestVerifyGarbageSignatureAborts(t *testing.T) {
	signer := newSigner(t, "alice@semver-trust.test", epoch, 0)
	_, err := Verify([]byte("payload\n"), "not an armored signature", keyring(t, signer), epoch)
	if !errors.Is(err, ErrBadSignature) {
		t.Errorf("error = %v, want ErrBadSignature", err)
	}
}

func TestVerifyNilKeyringAborts(t *testing.T) {
	signer := newSigner(t, "alice@semver-trust.test", epoch, 0)
	payload := []byte("payload\n")
	sig := sign(t, signer, payload, epoch)

	if _, err := Verify(payload, sig, nil, epoch); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("error = %v, want ErrUnknownKey", err)
	}
}

// A keyring assembled by concatenating per-key `gpg --export --armor`
// outputs (several armor blocks) loads every key: a later block silently
// dropped would turn its signer's valid commits into aborts.
func TestParseKeyringReadsConcatenatedBlocks(t *testing.T) {
	alice := newSigner(t, "alice@semver-trust.test", epoch, 0)
	bob := newSigner(t, "bob@semver-trust.test", epoch, 0)
	aliceArmor, err := pgptest.ArmoredKeyring(alice)
	if err != nil {
		t.Fatal(err)
	}
	bobArmor, err := pgptest.ArmoredKeyring(bob)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload\n")
	sig := sign(t, bob, payload, epoch)

	// Newline-separated blocks (gpg's shape) and blocks jammed together with
	// no separator at all (go-crypto's armor encoder ends without a newline)
	// both load whole.
	for name, data := range map[string][]byte{
		"newline-separated": append(aliceArmor, bobArmor...),
		"no-separator":      append(bytes.TrimRight(aliceArmor, "\n"), bobArmor...),
	} {
		t.Run(name, func(t *testing.T) {
			kr, err := ParseKeyring(data)
			if err != nil {
				t.Fatalf("ParseKeyring: %v", err)
			}
			// The second block's key verifies — it was not dropped.
			got, err := Verify(payload, sig, kr, epoch)
			if err != nil {
				t.Fatalf("Verify with second-block key: %v", err)
			}
			if got.Principal != "bob@semver-trust.test" {
				t.Errorf("principal = %q, want bob@semver-trust.test", got.Principal)
			}
		})
	}
}

func TestParseKeyringRejectsGarbage(t *testing.T) {
	if _, err := ParseKeyring([]byte("not a keyring")); err == nil {
		t.Error("ParseKeyring accepted garbage")
	}
}

func TestParseKeyringRejectsEmpty(t *testing.T) {
	// A structurally valid armor block with no keys grants nothing and is
	// rejected rather than silently trusted-empty.
	if _, err := ParseKeyring([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\n-----END PGP PUBLIC KEY BLOCK-----\n")); err == nil {
		t.Error("ParseKeyring accepted an empty keyring")
	}
}
