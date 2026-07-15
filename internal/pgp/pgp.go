// SPDX-License-Identifier: Apache-2.0

// Package pgp verifies OpenPGP (GPG) detached signatures against an
// explicitly injected public keyring — the OpenPGP key family of the
// commit-signature seam (spec §4.2; fixture plan §2.1 fail-closed rider).
//
// The keyring is injected trust material and the verification instant is an
// injected clock (ADR-018): nothing here reads ambient key stores or the
// wall clock. Key validity — creation, expiry via self-signature, revocation
// — is evaluated at the injected instant by threading it through
// packet.Config.Time.
//
// The implementation uses github.com/ProtonMail/go-crypto/openpgp (the
// maintained fork go-git already depends on), never the frozen
// golang.org/x/crypto/openpgp.
package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Failure classes. They mirror the SSH registry's unknown/revoked/invalid
// split so the vcs layer can map them onto its existing sentinels
// (vcs.ErrUnknownSigner, vcs.ErrRevokedSigner, vcs.ErrInvalidSignature) and
// error identity stays uniform across key families. This package stays free
// of the sshsig import — the mapping is the vcs layer's job.
var (
	// ErrUnknownKey — the signing key is absent from the injected keyring.
	ErrUnknownKey = errors.New("pgp: signing key is not in the injected keyring")
	// ErrKeyInvalidAtInstant — the signing key is in the keyring but not
	// valid at the verification instant (not yet created, expired via
	// self-signature, or revoked): distinct from never-enrolled.
	ErrKeyInvalidAtInstant = errors.New("pgp: signing key is not valid at the verification instant")
	// ErrBadSignature — the signature does not verify over the payload
	// (tampering, corruption, or a signature for other content).
	ErrBadSignature = errors.New("pgp: signature does not verify")
)

// Keyring is a parsed OpenPGP public keyring: the injected trust material
// for the GPG key family, the analog of the SSH allowed-signers registry.
type Keyring struct {
	entities openpgp.EntityList
}

// ParseKeyring parses an armored OpenPGP public keyring: one or more public
// keys, in one armor block or several concatenated blocks — the shape
// `gpg --export --armor` produces per key, so a keyring assembled by
// concatenating exports loads whole. (go-crypto's ReadArmoredKeyRing reads
// only the first block; stopping there would silently drop every later
// key.) A keyring that fails to parse is an error, not a skip: it is the
// root of GPG-family trust, and a silently dropped key would turn a valid
// signer into an abort.
func ParseKeyring(data []byte) (*Keyring, error) {
	var entities openpgp.EntityList
	for _, blockBytes := range splitArmorBlocks(data) {
		// armor.Decode may over-read past a block's end, so each block gets
		// its own reader — never a shared one.
		block, err := armor.Decode(bytes.NewReader(blockBytes))
		if err != nil {
			return nil, fmt.Errorf("pgp: parsing armored keyring: %w", err)
		}
		if block.Type != openpgp.PublicKeyType {
			return nil, fmt.Errorf("pgp: keyring block is %q, want %q", block.Type, openpgp.PublicKeyType)
		}
		el, err := openpgp.ReadKeyRing(block.Body)
		if err != nil {
			return nil, fmt.Errorf("pgp: parsing armored keyring: %w", err)
		}
		entities = append(entities, el...)
	}
	if len(entities) == 0 {
		return nil, errors.New("pgp: keyring contains no keys")
	}
	return &Keyring{entities: entities}, nil
}

// splitArmorBlocks cuts data into its armor blocks, one slice per
// BEGIN..END span (unterminated trailing spans included, so their error
// surfaces in armor.Decode rather than as a silent drop).
func splitArmorBlocks(data []byte) [][]byte {
	var (
		begin  = []byte("-----BEGIN PGP ")
		end    = []byte("-----END PGP ")
		blocks [][]byte
	)
	for {
		start := bytes.Index(data, begin)
		if start < 0 {
			return blocks
		}
		stop := len(data)
		if i := bytes.Index(data[start+len(begin):], end); i >= 0 {
			// The END line closes with the trailing dashes; a newline is not
			// guaranteed (gpg emits one, go-crypto's encoder does not).
			endLine := start + len(begin) + i + len(end)
			if j := bytes.Index(data[endLine:], []byte("-----")); j >= 0 {
				stop = endLine + j + len("-----")
			}
		}
		blocks = append(blocks, data[start:stop])
		data = data[stop:]
	}
}

// Verified is a successful OpenPGP verification: the principal the signing
// key resolves to and the key's fingerprint — the same shape the SSH path
// produces, so the layers above treat both families uniformly.
type Verified struct {
	// Principal is the verified key's primary identity: the name-addr email
	// when the identity carries one, else the full user-ID string.
	Principal string
	// Fingerprint is the signing entity's primary-key fingerprint (upper-case
	// hex, the form gpg prints).
	Fingerprint string
}

// Verify checks the armored detached signature over payload against the
// injected keyring at the injected instant. go-crypto evaluates key validity
// (expiry via self-signature, revocation, signature expiry) at
// packet.Config.Time, which is pinned to at — never the wall clock
// (ADR-018); a key created after at is rejected explicitly.
func Verify(payload []byte, armoredSig string, keyring *Keyring, at time.Time) (Verified, error) {
	if keyring == nil {
		return Verified{}, ErrUnknownKey
	}
	config := &packet.Config{Time: func() time.Time { return at }}
	signer, err := openpgp.CheckArmoredDetachedSignature(
		keyring.entities, bytes.NewReader(payload), strings.NewReader(armoredSig), config)
	switch {
	case err == nil:
		// fall through to the creation-time check below
	case errors.Is(err, pgperrors.ErrUnknownIssuer):
		return Verified{}, ErrUnknownKey
	case errors.Is(err, pgperrors.ErrKeyRevoked),
		errors.Is(err, pgperrors.ErrKeyExpired),
		errors.Is(err, pgperrors.ErrSignatureExpired):
		return Verified{}, fmt.Errorf("%w: %v", ErrKeyInvalidAtInstant, err)
	default:
		return Verified{}, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}

	// go-crypto checks expiry and revocation at config time but not whether
	// the key existed yet: a key created after the verification instant is
	// not valid material at that instant.
	if signer.PrimaryKey.CreationTime.After(at) {
		return Verified{}, fmt.Errorf("%w: key created %s, after the verification instant %s",
			ErrKeyInvalidAtInstant,
			signer.PrimaryKey.CreationTime.UTC().Format(time.RFC3339),
			at.UTC().Format(time.RFC3339))
	}

	return Verified{
		Principal:   principal(signer),
		Fingerprint: fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint),
	}, nil
}

// principal extracts the identity string for a verified entity: the primary
// identity's email (the analog of an allowed-signers principal), falling
// back to the full user-ID string, then the key ID for an identity-less key
// — never empty, because layers above key policy decisions off it.
func principal(e *openpgp.Entity) string {
	ident := e.PrimaryIdentity()
	if ident == nil {
		return fmt.Sprintf("key-id %X", e.PrimaryKey.Fingerprint)
	}
	if ident.UserId != nil && ident.UserId.Email != "" {
		return ident.UserId.Email
	}
	return ident.Name
}

// Principals returns the primary-identity principal of every key in the keyring,
// de-duplicated in keyring order. Each value is exactly the principal Verify
// returns for a signature by that key — so callers enumerating authorized
// signers (§5.4 policy transition) match what commit verification produces.
func (k *Keyring) Principals() []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range k.entities {
		p := principal(e)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
