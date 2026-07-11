// SPDX-License-Identifier: Apache-2.0

// Package attest verifies SemVer-Trust attestations: DSSE envelopes carrying
// in-toto Statements with the frozen v0.1 predicate types (spec §4.3, §8.1),
// signed per ADR-022 — an OpenSSH SSHSIG over the DSSE pre-authentication
// encoding in the attestation namespace, with the envelope keyid an
// untrusted lookup hint only.
//
// Verification is ADR-018-shaped from its first draft: the attestation-signer
// registry, the predicate schemas, and the verification clock are injected —
// no ambient trust material, no wall clock, no network. §8.2 makes the
// signature inside the attestation the trust anchor; storage (store.go) is
// never trusted.
//
// The two acceptance-critical failure classes are distinct by construction:
// a schema-invalid payload under a genuine signature (ErrSchemaInvalid) is a
// different defect from a signature that does not cover the bytes
// (ErrSignatureInvalid) — a well-signed lie about shape versus a forgery.
package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/crypto/ssh"

	sshsigpkg "github.com/semver-trust/semver-trust-go/internal/sshsig"
)

// Namespace is the ADR-022 SSHSIG namespace binding a signature to
// attestation use: a git commit signature can never double as an attestation
// signature, and vice versa.
const Namespace = "attestation@semver-trust.dev"

// PayloadType is the DSSE payload type for in-toto Statements.
const PayloadType = "application/vnd.in-toto+json"

// StatementType is the in-toto Statement v1 type URI (spec §8).
const StatementType = "https://in-toto.io/Statement/v1"

// The frozen predicate-type URIs (spec §4.3, §8.1; ADR-013).
const (
	PredicateRelease = "https://semver-trust.dev/release/v0.1"
	PredicateReview  = "https://semver-trust.dev/review/v0.1"
)

// Verification failure classes. Every one is an abort (§5.2, §8.2).
var (
	// ErrMalformedEnvelope — not a DSSE envelope this verifier understands
	// (wrong payload type, missing or multiple signatures, bad base64).
	ErrMalformedEnvelope = errors.New("malformed DSSE envelope")
	// ErrSignatureInvalid — the signature does not verify over the
	// envelope's PAE: tampering, corruption, or a signature for other bytes.
	ErrSignatureInvalid = errors.New("attestation signature does not verify")
	// ErrUnknownSigner — the signing key is absent from the injected
	// attestation-signer registry (alias of the shared sshsig sentinel).
	ErrUnknownSigner = sshsigpkg.ErrUnknownSigner
	// ErrRevokedSigner — enrolled but not valid at the verification instant
	// (alias of the shared sshsig sentinel).
	ErrRevokedSigner = sshsigpkg.ErrRevokedSigner
	// ErrUnsupportedPredicate — the statement's predicate type is not one of
	// the frozen URIs this verifier carries schemas for. Fail closed: an
	// attestation this verifier cannot validate anchors nothing.
	ErrUnsupportedPredicate = errors.New("unsupported predicate type")
	// ErrSchemaInvalid — the signature is genuine but the payload does not
	// validate against the predicate's schema: a well-signed lie about
	// shape, distinct from a forgery by construction.
	ErrSchemaInvalid = errors.New("attestation payload does not validate against its schema")
)

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature. KeyID is an untrusted lookup hint
// (ADR-022): verification resolves the key embedded in the SSHSIG against
// the injected registry and never trusts KeyID.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Statement is the verified result: the in-toto Statement's identity fields
// plus the raw payload for downstream consumers (the provenance vector,
// decision block, and so on).
type Statement struct {
	PredicateType string
	Subjects      []Subject
	Signer        string
	Payload       json.RawMessage
}

// Subject is an in-toto subject: a name bound to a digest set.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Verifier verifies envelopes against injected trust material (ADR-018): the
// attestation-signer registry and the predicate schemas, compiled once.
type Verifier struct {
	signers []sshsigpkg.AllowedSigner
	schemas map[string]*jsonschema.Schema
}

// NewVerifier compiles the injected predicate schemas (predicate-type URI →
// raw JSON Schema bytes) and holds the injected registry. Schemas are
// compiled with format assertion enabled, so RFC 3339 timestamps are
// enforced, and resolution is strictly offline.
func NewVerifier(signers []sshsigpkg.AllowedSigner, schemas map[string][]byte) (*Verifier, error) {
	compiled := make(map[string]*jsonschema.Schema, len(schemas))
	for predicateType, raw := range schemas {
		schema, err := compileSchema(raw)
		if err != nil {
			return nil, fmt.Errorf("attest: schema for %s: %w", predicateType, err)
		}
		compiled[predicateType] = schema
	}
	return &Verifier{signers: signers, schemas: compiled}, nil
}

// compileSchema compiles one raw JSON Schema with format assertion enabled
// (RFC 3339 timestamps are enforced) and strictly offline resolution. Both
// the verifier and the emitter compile through here, so emission validates
// against exactly the schema verification will apply.
func compileSchema(raw []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	const url = "schema.json"
	if err := compiler.AddResource(url, doc); err != nil {
		return nil, err
	}
	return compiler.Compile(url)
}

// PAE computes the DSSE v1 pre-authentication encoding.
func PAE(payloadType string, payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("DSSEv1 ")
	buf.WriteString(strconv.Itoa(len(payloadType)))
	buf.WriteByte(' ')
	buf.WriteString(payloadType)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(len(payload)))
	buf.WriteByte(' ')
	buf.Write(payload)
	return buf.Bytes()
}

// Verify verifies an envelope at the injected verification instant: parse,
// resolve the SSHSIG's embedded key against the registry (the keyid hint is
// never consulted for trust), verify the signature over the PAE, then
// validate the payload against the predicate's schema. Order matters for
// error classes: enrollment resolves before cryptography (an unenrolled
// key's mathematically valid signature is still an abort, reported as
// enrollment), and schema validation runs only under a genuine signature —
// ErrSchemaInvalid always means "well-signed lie about shape".
func (v *Verifier) Verify(envelope []byte, at time.Time) (Statement, error) {
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return Statement{}, fmt.Errorf("attest: %w: %v", ErrMalformedEnvelope, err)
	}
	if env.PayloadType != PayloadType || len(env.Signatures) != 1 {
		return Statement{}, fmt.Errorf(
			"attest: %w: payloadType %q, %d signatures",
			ErrMalformedEnvelope, env.PayloadType, len(env.Signatures),
		)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Statement{}, fmt.Errorf("attest: %w: payload: %v", ErrMalformedEnvelope, err)
	}
	sigArmor, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return Statement{}, fmt.Errorf("attest: %w: sig: %v", ErrMalformedEnvelope, err)
	}

	sig, err := sshsigpkg.Parse(string(sigArmor))
	if err != nil {
		return Statement{}, fmt.Errorf("attest: %w: %v", ErrSignatureInvalid, err)
	}
	if sig.Namespace != Namespace {
		return Statement{}, fmt.Errorf(
			"attest: signature namespace %q is not %q: %w", sig.Namespace, Namespace, ErrSignatureInvalid,
		)
	}

	principal, err := sshsigpkg.Resolve(sig.PublicKey, v.signers, Namespace, at)
	if err != nil {
		return Statement{}, fmt.Errorf("attest: %w", err)
	}
	if err := sig.Verify(PAE(env.PayloadType, payload)); err != nil {
		return Statement{}, fmt.Errorf("attest: %w: %v", ErrSignatureInvalid, err)
	}

	var stmt struct {
		Type          string          `json:"_type"`
		Subject       []Subject       `json:"subject"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return Statement{}, fmt.Errorf("attest: %w: statement: %v", ErrSchemaInvalid, err)
	}
	schema, ok := v.schemas[stmt.PredicateType]
	if !ok {
		return Statement{}, fmt.Errorf("attest: %q: %w", stmt.PredicateType, ErrUnsupportedPredicate)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		return Statement{}, fmt.Errorf("attest: %w: %v", ErrSchemaInvalid, err)
	}
	if err := schema.Validate(doc); err != nil {
		return Statement{}, fmt.Errorf("attest: %w: %v", ErrSchemaInvalid, err)
	}

	return Statement{
		PredicateType: stmt.PredicateType,
		Subjects:      stmt.Subject,
		Signer:        principal,
		Payload:       payload,
	}, nil
}

// Fingerprint returns the SHA256 fingerprint of an allowed signer's key —
// the value envelope keyids carry as their (untrusted) hint.
func Fingerprint(s sshsigpkg.AllowedSigner) string {
	return ssh.FingerprintSHA256(s.Key)
}
