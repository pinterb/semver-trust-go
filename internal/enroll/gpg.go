// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/semver-trust/semver-trust-go/internal/pgp"
)

// GPGResult is a validated GPG keyring enrollment ready to print or write.
type GPGResult struct {
	// NewContent is the whole new keyring (existing armor + the candidate armor),
	// already re-parsed — ready for WriteRegistry.
	NewContent []byte
	// NewFingerprints are the primary-key fingerprints this enrollment introduces
	// (mandatory identity disclosure).
	NewFingerprints []string
	// CandidatePrincipals are the principals of the candidate key(s) — ALWAYS the
	// full set, so the disclosure names whose authority is being added even when the
	// email already exists in the keyring (a key rotation, where NewPrincipals is
	// empty). This is the identity the human must see before committing.
	CandidatePrincipals []string
	// NewPrincipals are the principals introduced relative to the existing keyring —
	// supplemental delta, empty on a same-email rotation.
	NewPrincipals []string
	// AllPrincipals are the principals after the append.
	AllPrincipals []string
}

// BuildGPG validates an armored candidate public key against the existing keyring
// and builds the appended result. It refuses private-key material loudly
// (pgp.ErrPrivateKeyMaterial — a keyring is public trust material), refuses a broken
// existing keyring, and requires at least one NEW key: a candidate whose every key
// is already enrolled is a refusal, not a silent no-op. The whole result is
// re-parsed with pgp.ParseKeyring before returning — the tool never writes a keyring
// it would itself reject (ADR-039).
func BuildGPG(candidate, existing []byte) (*GPGResult, error) {
	candKR, err := pgp.ParseKeyring(candidate)
	if err != nil {
		if errors.Is(err, pgp.ErrPrivateKeyMaterial) {
			return nil, fmt.Errorf("refusing to enroll private key material — export the PUBLIC key (gpg --armor --export <keyid>): %w", err)
		}
		return nil, fmt.Errorf("the --gpg-pubkey input is not an armored public keyring: %w", err)
	}

	existingFPs := map[string]bool{}
	existingPrincipals := map[string]bool{}
	if len(existing) > 0 {
		existingKR, err := pgp.ParseKeyring(existing)
		if err != nil {
			return nil, fmt.Errorf("the existing keyring does not parse — fix it first: %w", err)
		}
		for _, fp := range existingKR.Fingerprints() {
			existingFPs[fp] = true
		}
		for _, p := range existingKR.Principals() {
			existingPrincipals[p] = true
		}
	}

	var newFPs []string
	for _, fp := range candKR.Fingerprints() {
		if !existingFPs[fp] {
			newFPs = append(newFPs, fp)
		}
	}
	if len(newFPs) == 0 {
		return nil, errors.New("every key in the input is already enrolled — nothing to add")
	}
	var newPrincipals []string
	for _, p := range candKR.Principals() {
		if !existingPrincipals[p] {
			newPrincipals = append(newPrincipals, p)
		}
	}

	newContent := appendKeyring(existing, candidate)
	wholeKR, err := pgp.ParseKeyring(newContent)
	if err != nil {
		return nil, fmt.Errorf("the resulting keyring does not parse: %w", err)
	}

	return &GPGResult{
		NewContent:          newContent,
		NewFingerprints:     newFPs,
		CandidatePrincipals: candKR.Principals(),
		NewPrincipals:       newPrincipals,
		AllPrincipals:       wholeKR.Principals(),
	}, nil
}

// appendKeyring concatenates the armored candidate onto the existing keyring. Armor
// blocks are self-delimiting, so appending the validated candidate bytes verbatim
// (with a separating newline) is the natural, lossless keyring "append".
func appendKeyring(existing, candidate []byte) []byte {
	if len(existing) == 0 {
		return append([]byte(nil), candidate...)
	}
	var buf bytes.Buffer
	buf.Write(existing)
	if !bytes.HasSuffix(existing, []byte("\n")) {
		buf.WriteByte('\n')
	}
	buf.Write(candidate)
	return buf.Bytes()
}
