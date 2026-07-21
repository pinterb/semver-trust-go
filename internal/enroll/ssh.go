// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

// SSHResult is a validated SSH allowed-signers enrollment ready to print or write.
type SSHResult struct {
	// Line is the byte-exact registry line (no trailing newline) — the material
	// printed in front of the human (ADR-038).
	Line string
	// Fingerprint is ssh.FingerprintSHA256 of the enrolled key — the mandatory
	// identity disclosure.
	Fingerprint string
	// Warn is a non-fatal note (e.g. this principal already has a different key);
	// empty when there is nothing to flag.
	Warn string
	// NewContent is the whole new registry file (existing bytes + the line), already
	// re-parsed and self-checked — ready for WriteRegistry.
	NewContent []byte
}

// BuildSSH validates and builds an SSH allowed-signers enrollment for pub under
// principal in namespace, appending to the existing registry bytes. It refuses a
// broken existing registry (the tool never launders a broken registry, ADR-039), a
// duplicate key ("already enrolled as <principal>"), and a key already present in
// crossRegistry — the two-key distinctness check (ADR-022/040): a commit key must
// not also be an attestation key. It WARNs (non-fatal) when the principal is already
// enrolled under a different key (multiple keys per principal are legal). Before
// returning, the whole new content is self-checked with the verifier's own
// sshsig.Resolve in namespace at `at`, so the enrollment is proven to resolve before
// the human ever commits it.
func BuildSSH(pub ssh.PublicKey, principal, namespace string, existing, crossRegistry []byte, at time.Time) (*SSHResult, error) {
	line, err := sshsig.FormatEnrollmentLine(principal, namespace, pub)
	if err != nil {
		return nil, err
	}
	fp := ssh.FingerprintSHA256(pub)

	existingSigners, err := sshsig.ParseAllowedSigners(existing)
	if err != nil {
		return nil, fmt.Errorf("the existing registry does not parse — fix it first: %w", err)
	}
	var warn string
	for _, s := range existingSigners {
		if s.Key != nil && ssh.FingerprintSHA256(s.Key) == fp {
			who := "an existing entry"
			if len(s.Principals) > 0 {
				who = s.Principals[0]
			}
			return nil, fmt.Errorf("this key is already enrolled as %s", who)
		}
		for _, p := range s.Principals {
			if p == principal {
				warn = fmt.Sprintf("%s is already enrolled under a different key; appending an additional key (multiple keys per principal are legal)", principal)
			}
		}
	}

	// ADR-040: the key must not appear in the other registry — commit and
	// attestation keys must be distinct.
	if len(crossRegistry) > 0 {
		crossSigners, err := sshsig.ParseAllowedSigners(crossRegistry)
		if err != nil {
			return nil, fmt.Errorf("the other registry does not parse — fix it first: %w", err)
		}
		for _, s := range crossSigners {
			if s.Key != nil && ssh.FingerprintSHA256(s.Key) == fp {
				return nil, errors.New("this key is already enrolled in the other registry — commit and attestation keys must be distinct (ADR-022/040)")
			}
		}
	}

	newContent := appendLine(existing, line)

	// Self-check: the resulting registry must parse, and the verifier's own resolver
	// must accept the appended key in the target namespace at `at`.
	newSigners, err := sshsig.ParseAllowedSigners(newContent)
	if err != nil {
		return nil, fmt.Errorf("the resulting registry does not parse: %w", err)
	}
	if _, err := sshsig.Resolve(pub, newSigners, namespace, at); err != nil {
		return nil, fmt.Errorf("self-check failed — the appended line does not resolve in namespace %q: %w", namespace, err)
	}

	return &SSHResult{Line: line, Fingerprint: fp, Warn: warn, NewContent: newContent}, nil
}

// appendLine returns existing with line appended as a new final line, ensuring a
// separating newline before it and a trailing newline after.
func appendLine(existing []byte, line string) []byte {
	var buf bytes.Buffer
	buf.Write(existing)
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		buf.WriteByte('\n')
	}
	buf.WriteString(line)
	buf.WriteByte('\n')
	return buf.Bytes()
}
