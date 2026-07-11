// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/crypto/ssh"

	sshsigpkg "github.com/semver-trust/semver-trust-go/internal/sshsig"
)

// This file is the emission half of the package: it builds §4.3 review
// statements and signs them into ADR-022 DSSE envelopes. Two riders govern
// everything here:
//
//   - Signed bytes are frozen (crypto fixture plan §6): the payload is
//     schema-validated BEFORE signing, and an invalid payload is refused —
//     a schema-invalid attestation can only ever exist as a hand-built test
//     double, never as this emitter's output.
//   - Emit-then-verify, never emit blind: every envelope is run back through
//     the real Verifier (with the signing key enrolled) before it is
//     returned. An envelope that does not verify is not output.

// Reviewer is one §4.3 reviewer entry: a verified identity, its class, and
// the verdict recorded at review time. Agent and Model annotate agent
// reviewers (§3.3) and are omitted when empty.
type Reviewer struct {
	Identity string
	Class    string // "human" | "agent"
	Verdict  string // "approved" | "changes_requested" | "commented"
	Agent    string // optional: reviewing tool/version, e.g. "claude-code/2.8"
	Model    string // optional: model identifier
}

// Independence carries the §3.3 independence assertions for agent review.
// They are assertions by the attesting workflow, not verifiable facts, and
// the schema records them as such.
type Independence struct {
	SeparateExecutionContext bool
	DistinctIdentity         bool
}

// ReviewInput is everything a §4.3 review statement is built from. The
// timestamp is injected (ADR-018): callers read the clock at the process
// boundary, never here.
type ReviewInput struct {
	// Subjects are the covered commit SHAs; each becomes an in-toto subject
	// binding the SHA as both name and gitCommit digest.
	Subjects []string
	// Reviewers is the §4.3 reviewer list (at least one).
	Reviewers []Reviewer
	// PullRequest is the PR/MR reference (URL or id).
	PullRequest string
	// MergeStrategy is "merge", "squash", or "rebase".
	MergeStrategy string
	// Timestamp is the merge/review instant, injected by the caller.
	Timestamp time.Time
	// Independence optionally carries the §3.3 assertions.
	Independence *Independence
}

// The wire shapes of the review statement. Field order here is the payload's
// byte order: encoding/json marshals struct fields in declaration order, so
// the serialized statement is stable across runs — which matters, because
// the signed bytes are frozen the moment Sign covers them.
type reviewStatementJSON struct {
	Type          string              `json:"_type"`
	Subject       []Subject           `json:"subject"`
	PredicateType string              `json:"predicateType"`
	Predicate     reviewPredicateJSON `json:"predicate"`
}

type reviewPredicateJSON struct {
	Reviewers     []reviewerJSON    `json:"reviewers"`
	PullRequest   string            `json:"pull_request"`
	MergeStrategy string            `json:"merge_strategy"`
	Independence  *independenceJSON `json:"independence,omitempty"`
	Timestamp     string            `json:"timestamp"`
}

type reviewerJSON struct {
	Identity string `json:"identity"`
	Class    string `json:"class"`
	Verdict  string `json:"verdict"`
	Agent    string `json:"agent,omitempty"`
	Model    string `json:"model,omitempty"`
}

type independenceJSON struct {
	SeparateExecutionContext bool `json:"separate_execution_context"`
	DistinctIdentity         bool `json:"distinct_identity"`
}

// BuildReviewStatement builds the serialized §4.3 in-toto Statement for a
// review: subjects are the covered commit SHAs (name + gitCommit digest),
// the predicate type is the frozen PredicateReview URI, and the timestamp is
// the injected instant in RFC 3339 UTC. It only shapes bytes — schema
// validation happens in Emit, before any signing.
func BuildReviewStatement(in ReviewInput) ([]byte, error) {
	if len(in.Subjects) == 0 {
		return nil, errors.New("attest: review statement needs at least one subject commit")
	}
	if len(in.Reviewers) == 0 {
		return nil, errors.New("attest: review statement needs at least one reviewer")
	}
	if in.Timestamp.IsZero() {
		return nil, errors.New("attest: review statement needs an injected timestamp (ADR-018: no wall clock here)")
	}

	subjects := make([]Subject, 0, len(in.Subjects))
	for _, sha := range in.Subjects {
		subjects = append(subjects, Subject{Name: sha, Digest: map[string]string{"gitCommit": sha}})
	}
	reviewers := make([]reviewerJSON, 0, len(in.Reviewers))
	for _, r := range in.Reviewers {
		reviewers = append(reviewers, reviewerJSON(r))
	}
	var independence *independenceJSON
	if in.Independence != nil {
		independence = &independenceJSON{
			SeparateExecutionContext: in.Independence.SeparateExecutionContext,
			DistinctIdentity:         in.Independence.DistinctIdentity,
		}
	}

	return json.Marshal(reviewStatementJSON{
		Type:          StatementType,
		Subject:       subjects,
		PredicateType: PredicateReview,
		Predicate: reviewPredicateJSON{
			Reviewers:     reviewers,
			PullRequest:   in.PullRequest,
			MergeStrategy: in.MergeStrategy,
			Independence:  independence,
			Timestamp:     in.Timestamp.UTC().Format(time.RFC3339),
		},
	})
}

// ReviewEmitter signs review statements into DSSE envelopes per ADR-022. It
// holds the signing key, the compiled review schema (the refuse-to-sign
// gate), and a self-verifier with exactly the signing key enrolled for the
// attestation namespace (the refuse-to-output gate).
type ReviewEmitter struct {
	signer       ssh.Signer
	schema       *jsonschema.Schema
	selfVerifier *Verifier
}

// NewReviewEmitter builds an emitter from a signer and the raw review-v0.1
// JSON Schema bytes (injected, like every other piece of trust material —
// the CLI wires the vendored conformance copy).
func NewReviewEmitter(signer ssh.Signer, reviewSchema []byte) (*ReviewEmitter, error) {
	schema, err := compileSchema(reviewSchema)
	if err != nil {
		return nil, fmt.Errorf("attest: review schema: %w", err)
	}
	selfVerifier, err := NewVerifier([]sshsigpkg.AllowedSigner{{
		Principals: []string{ssh.FingerprintSHA256(signer.PublicKey())},
		Namespaces: []string{Namespace},
		Key:        signer.PublicKey(),
	}}, map[string][]byte{PredicateReview: reviewSchema})
	if err != nil {
		return nil, err
	}
	return &ReviewEmitter{signer: signer, schema: schema, selfVerifier: selfVerifier}, nil
}

// Emission is a signed review attestation: the DSSE envelope bytes, the
// statement payload they carry, and the signer's SHA256 fingerprint (the
// envelope's untrusted keyid hint, ADR-022).
type Emission struct {
	Envelope []byte
	Payload  []byte
	KeyID    string
}

// Emit builds, validates, signs, and self-verifies a review attestation:
//
//  1. Serialize the statement (BuildReviewStatement).
//  2. Schema-validate the payload BEFORE signing — signed bytes are frozen,
//     so an invalid payload is refused, never signed (fixture plan §6 rider).
//  3. SSHSIG-sign the DSSE PAE in the attestation namespace (ADR-022).
//  4. Run the finished envelope through the real Verifier with the signing
//     key enrolled — refuse to output an envelope that does not verify.
//
// Verification in step 4 runs at the statement's own timestamp, the only
// instant available without a wall clock (ADR-018).
func (e *ReviewEmitter) Emit(in ReviewInput) (Emission, error) {
	payload, err := BuildReviewStatement(in)
	if err != nil {
		return Emission{}, err
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		return Emission{}, fmt.Errorf("attest: refusing to sign: %w: %v", ErrSchemaInvalid, err)
	}
	if err := e.schema.Validate(doc); err != nil {
		return Emission{}, fmt.Errorf("attest: refusing to sign: %w: %v", ErrSchemaInvalid, err)
	}

	armored, err := sshsigpkg.Sign(e.signer, Namespace, PAE(PayloadType, payload))
	if err != nil {
		return Emission{}, fmt.Errorf("attest: %w", err)
	}
	keyid := ssh.FingerprintSHA256(e.signer.PublicKey())
	envelope, err := json.Marshal(Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID: keyid,
			Sig:   base64.StdEncoding.EncodeToString([]byte(armored)),
		}},
	})
	if err != nil {
		return Emission{}, fmt.Errorf("attest: %w", err)
	}

	if _, err := e.selfVerifier.Verify(envelope, in.Timestamp); err != nil {
		return Emission{}, fmt.Errorf("attest: emitted envelope failed self-verification, refusing to output it: %w", err)
	}
	return Emission{Envelope: envelope, Payload: payload, KeyID: keyid}, nil
}

// StoreForSubjects stores one envelope under each subject SHA, so a verifier
// listing attestations per commit (§10 step 3) finds it under every commit
// it covers. It returns the refs in subject order.
func StoreForSubjects(s Store, subjects []string, envelope []byte) ([]string, error) {
	refs := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		ref, err := s.Put(subject, envelope)
		if err != nil {
			return refs, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}
