// SPDX-License-Identifier: Apache-2.0

package sshsig

import (
	"strings"
	"testing"
	"time"
)

const testKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKulHisNBN0fbk5LFMzdZ4+vCIt4Kmsjhj9NkzdjljmH"

func TestParseAllowedSigners(t *testing.T) {
	data := `# comment line

alice@example.test namespaces="git" ` + testKeyLine + ` a comment
bob@example.test,robert@example.test ` + testKeyLine + `
carol@example.test namespaces="git",valid-before="20251231" ` + testKeyLine + `
dave@example.test cert-authority valid-after="20260101" ` + testKeyLine + `
`
	signers, err := ParseAllowedSigners([]byte(data))
	if err != nil {
		t.Fatalf("ParseAllowedSigners: %v", err)
	}
	if len(signers) != 4 {
		t.Fatalf("parsed %d signers, want 4", len(signers))
	}

	alice := signers[0]
	if alice.Principals[0] != "alice@example.test" || len(alice.Namespaces) != 1 || alice.Namespaces[0] != "git" {
		t.Errorf("alice = %+v", alice)
	}
	if !alice.forNamespace("git") || alice.forNamespace("file") {
		t.Error("alice namespace scoping wrong")
	}

	bob := signers[1]
	if len(bob.Principals) != 2 || bob.Principals[1] != "robert@example.test" {
		t.Errorf("bob principals = %v", bob.Principals)
	}
	if !bob.forNamespace("anything") {
		t.Error("no-namespaces entry should cover any namespace")
	}

	carol := signers[2]
	epoch := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if carol.validAt(epoch) {
		t.Error("carol should be invalid at the epoch (valid-before 20251231)")
	}
	if !carol.validAt(time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("carol should be valid before her window closes")
	}

	dave := signers[3]
	if !dave.CertAuthority {
		t.Error("dave should be cert-authority")
	}
	if dave.validAt(time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)) {
		t.Error("dave should be invalid before valid-after")
	}
	if !dave.validAt(epoch) {
		t.Error("dave should be valid at the epoch")
	}
}

// Malformed lines are errors, not skips: a silently dropped enrollment line
// could turn a valid signer into an abort, or a malformed revocation window
// into a grant.
func TestParseAllowedSignersRejects(t *testing.T) {
	cases := map[string]string{
		"too few fields":    "alice@example.test\n",
		"bad key":           "alice@example.test ssh-ed25519 not-base64!\n",
		"bad valid-before":  `alice@example.test valid-before="notadate" ` + testKeyLine + "\n",
		"missing key":       `alice@example.test namespaces="git"` + "\n",
		"garbage keyformat": "alice@example.test what even " + testKeyLine + "\n",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAllowedSigners([]byte(line)); err == nil {
				t.Errorf("accepted %q", strings.TrimSpace(line))
			}
		})
	}
}

func TestParseSignerTimeFormats(t *testing.T) {
	for v, want := range map[string]time.Time{
		"20260101":        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		"202601011530":    time.Date(2026, 1, 1, 15, 30, 0, 0, time.UTC),
		"20260101153045":  time.Date(2026, 1, 1, 15, 30, 45, 0, time.UTC),
		"20260101153045Z": time.Date(2026, 1, 1, 15, 30, 45, 0, time.UTC),
	} {
		got, err := parseSignerTime(v)
		if err != nil || !got.Equal(want) {
			t.Errorf("parseSignerTime(%q) = %v, %v; want %v", v, got, err, want)
		}
	}
}
