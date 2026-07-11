// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

// Consumes the DSSE attestation vectors from the ADR-021 vendored copy
// (conformance/vendor/crypto/attestations/): frozen envelopes verified
// against the injected attestation-signer registry and the vendored v0.1
// predicate schemas at the pinned verification instant.

type attVectorFile struct {
	SpecVersion      string      `json:"spec_version"`
	VerificationTime string      `json:"verification_time"`
	AllowedSigners   string      `json:"allowed_signers"`
	Vectors          []attVector `json:"vectors"`
}

type attVector struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Inputs struct {
		Envelope string `json:"envelope"`
	} `json:"inputs"`
	Expected struct {
		Outcome       string `json:"outcome"`
		Signer        string `json:"signer"`
		PredicateType string `json:"predicate_type"`
		Reason        string `json:"reason"`
	} `json:"expected"`
}

var reasonErrs = map[string]error{
	"schema_invalid":    ErrSchemaInvalid,
	"signature_invalid": ErrSignatureInvalid,
	"unknown_signer":    ErrUnknownSigner,
	"revoked_signer":    ErrRevokedSigner,
}

func vendorDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "vendor")
}

func newConformanceVerifier(t *testing.T, attDir string) *Verifier {
	t.Helper()
	registry, err := os.ReadFile(filepath.Join(attDir, "allowed_signers"))
	if err != nil {
		t.Fatalf("attestation registry missing (refresh via scripts/sync-conformance.py): %v", err)
	}
	signers, err := sshsig.ParseAllowedSigners(registry)
	if err != nil {
		t.Fatal(err)
	}
	schemas := map[string][]byte{}
	for predicateType, file := range map[string]string{
		PredicateRelease: "release-v0.1.json",
		PredicateReview:  "review-v0.1.json",
	} {
		data, err := os.ReadFile(filepath.Join(vendorDir(t), "schemas", file))
		if err != nil {
			t.Fatalf("vendored schema missing: %v", err)
		}
		schemas[predicateType] = data
	}
	verifier, err := NewVerifier(signers, schemas)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func TestConformanceAttestations(t *testing.T) {
	attDir := filepath.Join(vendorDir(t), "crypto", "attestations")
	data, err := os.ReadFile(filepath.Join(attDir, "attestation-vectors.json"))
	if err != nil {
		t.Fatalf("attestation vectors missing (refresh via scripts/sync-conformance.py): %v", err)
	}
	var vf attVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339, vf.VerificationTime)
	if err != nil {
		t.Fatal(err)
	}
	verifier := newConformanceVerifier(t, attDir)

	seen := 0
	for _, vec := range vf.Vectors {
		if vec.Kind != "dsse_attestation" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			envelope, err := os.ReadFile(filepath.Join(attDir, filepath.FromSlash(vec.Inputs.Envelope)))
			if err != nil {
				t.Fatal(err)
			}

			stmt, err := verifier.Verify(envelope, at)

			if vec.Expected.Outcome == "verified" {
				if err != nil {
					t.Fatalf("Verify: %v, want verified", err)
				}
				if stmt.Signer != vec.Expected.Signer {
					t.Errorf("signer = %q, want %q", stmt.Signer, vec.Expected.Signer)
				}
				if stmt.PredicateType != vec.Expected.PredicateType {
					t.Errorf("predicateType = %q, want %q", stmt.PredicateType, vec.Expected.PredicateType)
				}
				if len(stmt.Subjects) == 0 {
					t.Error("no subjects surfaced")
				}
				return
			}

			want, ok := reasonErrs[vec.Expected.Reason]
			if !ok {
				t.Fatalf("vector carries unknown reason %q", vec.Expected.Reason)
			}
			if err == nil {
				t.Fatalf("verification succeeded, want abort: %s", vec.Expected.Reason)
			}
			if !errors.Is(err, want) {
				t.Errorf("error = %v, want %v", err, want)
			}
			// The acceptance's distinctness clause: the failure must match
			// its own class and no other abort sentinel.
			for reason, sentinel := range reasonErrs {
				if reason != vec.Expected.Reason && errors.Is(err, sentinel) {
					t.Errorf("error %v also matches %s — classes are not distinct", err, reason)
				}
			}
		})
	}
	if seen == 0 {
		t.Error("no dsse_attestation vectors found")
	}
}

// TestVerifyUnsupportedPredicate pins the fail-closed path for predicate
// types this verifier has no schema for.
func TestVerifyUnsupportedPredicate(t *testing.T) {
	attDir := filepath.Join(vendorDir(t), "crypto", "attestations")
	registry, err := os.ReadFile(filepath.Join(attDir, "allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	signers, err := sshsig.ParseAllowedSigners(registry)
	if err != nil {
		t.Fatal(err)
	}
	// A verifier with no schemas at all: every predicate is unsupported.
	verifier, err := NewVerifier(signers, nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := os.ReadFile(filepath.Join(attDir, "envelopes", "release-valid.dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(envelope, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrUnsupportedPredicate) {
		t.Errorf("error = %v, want ErrUnsupportedPredicate", err)
	}
}
