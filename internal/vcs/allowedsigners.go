// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// AllowedSigner is one enrollment line of an OpenSSH allowed-signers
// registry (ssh-keygen(1) ALLOWED SIGNERS): the injected trust material
// human-identity verification consumes (§4.2, §9 [identity.human]
// allowed_signers, ADR-018).
type AllowedSigner struct {
	// Principals are the identities this key signs for.
	Principals []string
	// Namespaces restricts the signature namespaces the key is trusted for;
	// empty means any.
	Namespaces []string
	// ValidAfter/ValidBefore bound the enrollment window; zero values are
	// unbounded. The injected verification clock is tested against them —
	// enrolled-but-invalid at the verification instant is a distinct
	// failure from never-enrolled.
	ValidAfter  time.Time
	ValidBefore time.Time
	// CertAuthority marks a CA entry (certificate-signed keys). This
	// verifier does not support CA enrollment; such entries never match a
	// leaf key directly, so they grant nothing (fail closed).
	CertAuthority bool
	// Key is the enrolled public key.
	Key ssh.PublicKey
}

// ParseAllowedSigners parses an allowed-signers file. Lines that cannot be
// parsed are errors, not skips: the registry is the root of human-identity
// trust, and a silently dropped enrollment line could turn a valid signer
// into an abort (or, with a malformed revocation window, worse).
func ParseAllowedSigners(data []byte) ([]AllowedSigner, error) {
	var signers []AllowedSigner
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		signer, err := parseAllowedSignerLine(line)
		if err != nil {
			return nil, fmt.Errorf("allowed_signers line %d: %w", lineNo, err)
		}
		signers = append(signers, signer)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return signers, nil
}

func parseAllowedSignerLine(line string) (AllowedSigner, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return AllowedSigner{}, fmt.Errorf("want 'principals [options] keytype key', got %d fields", len(fields))
	}

	signer := AllowedSigner{Principals: strings.Split(fields[0], ",")}

	// Options sit between the principals and the key type as comma-separated
	// tokens (quotes protect commas): bare cert-authority, or name="value"
	// pairs. Unknown options are errors — a future revocation-relevant
	// option silently ignored would be a grant the file's author did not
	// intend.
	i := 1
	for ; i < len(fields); i++ {
		f := fields[i]
		if f != "cert-authority" && !strings.Contains(f, "=") {
			break // the key type begins here
		}
		for _, opt := range splitOptions(f) {
			if err := applyOption(&signer, opt); err != nil {
				return AllowedSigner{}, err
			}
		}
	}
	if len(fields)-i < 2 {
		return AllowedSigner{}, fmt.Errorf("missing key type and key")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fields[i] + " " + fields[i+1]))
	if err != nil {
		return AllowedSigner{}, fmt.Errorf("public key: %w", err)
	}
	signer.Key = key
	return signer, nil
}

func applyOption(signer *AllowedSigner, opt string) error {
	switch {
	case opt == "cert-authority":
		signer.CertAuthority = true
	case strings.HasPrefix(opt, "namespaces="):
		signer.Namespaces = strings.Split(unquote(opt[len("namespaces="):]), ",")
	case strings.HasPrefix(opt, "valid-after="):
		t, err := parseSignerTime(unquote(opt[len("valid-after="):]))
		if err != nil {
			return fmt.Errorf("valid-after: %w", err)
		}
		signer.ValidAfter = t
	case strings.HasPrefix(opt, "valid-before="):
		t, err := parseSignerTime(unquote(opt[len("valid-before="):]))
		if err != nil {
			return fmt.Errorf("valid-before: %w", err)
		}
		signer.ValidBefore = t
	default:
		return fmt.Errorf("unknown option %q", opt)
	}
	return nil
}

// splitOptions splits a comma-separated option field, honoring quotes.
func splitOptions(s string) []string {
	var out []string
	var current strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	return append(out, current.String())
}

// validAt reports whether the enrollment window contains the verification
// instant.
func (s AllowedSigner) validAt(at time.Time) bool {
	if !s.ValidAfter.IsZero() && at.Before(s.ValidAfter) {
		return false
	}
	if !s.ValidBefore.IsZero() && !at.Before(s.ValidBefore) {
		return false
	}
	return true
}

// forNamespace reports whether the enrollment covers a signature namespace.
func (s AllowedSigner) forNamespace(ns string) bool {
	if len(s.Namespaces) == 0 {
		return true
	}
	for _, n := range s.Namespaces {
		if n == ns {
			return true
		}
	}
	return false
}

func unquote(v string) string {
	return strings.Trim(v, `"`)
}

// parseSignerTime parses ssh-keygen's YYYYMMDD[HHMM[SS]] instants, with an
// optional Z suffix. Bare instants are read as UTC — the fixtures pin their
// windows and clock in UTC, and a verifier that read them in local time
// would verify differently per machine.
func parseSignerTime(v string) (time.Time, error) {
	v = strings.TrimSuffix(v, "Z")
	for _, layout := range []string{"20060102150405", "200601021504", "20060102"} {
		if len(v) == len(layout) {
			return time.Parse(layout, v)
		}
	}
	return time.Time{}, fmt.Errorf("invalid time %q (want YYYYMMDD[HHMM[SS]][Z])", v)
}
