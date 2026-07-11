// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

var emitEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func reviewSchemaBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vendorDir(t), "schemas", "review-v0.1.json"))
	if err != nil {
		t.Fatalf("reading review schema: %v", err)
	}
	return data
}

func newEmitTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func validReviewInput() ReviewInput {
	return ReviewInput{
		Subjects: []string{
			"e076050f6714ea6be852fce9c47ff65b05c911b3",
			"80e2be6297494cd2e3c85d2ace1c7579edac3f74",
		},
		Reviewers: []Reviewer{
			{Identity: "bob@semver-trust.test", Class: "human", Verdict: "approved"},
		},
		PullRequest:   "https://forge.semver-trust.test/platform/pull/7",
		MergeStrategy: "merge",
		Timestamp:     emitEpoch,
	}
}

// An emitted envelope must verify against an INDEPENDENT verifier whose
// registry enrolls the signing key for the attestation namespace — the same
// path `verify` takes — and yield the review statement it was built from.
func TestEmitReviewVerifiesIndependently(t *testing.T) {
	signer := newEmitTestSigner(t)
	emitter, err := NewReviewEmitter(signer, reviewSchemaBytes(t))
	if err != nil {
		t.Fatalf("NewReviewEmitter: %v", err)
	}

	in := validReviewInput()
	emission, err := emitter.Emit(in)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if emission.KeyID != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Errorf("KeyID = %q, want the signer's SHA256 fingerprint", emission.KeyID)
	}

	verifier, err := NewVerifier([]sshsig.AllowedSigner{{
		Principals: []string{"bob@semver-trust.test"},
		Namespaces: []string{Namespace},
		Key:        signer.PublicKey(),
	}}, map[string][]byte{PredicateReview: reviewSchemaBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := verifier.Verify(emission.Envelope, emitEpoch)
	if err != nil {
		t.Fatalf("independent Verify: %v", err)
	}
	if stmt.PredicateType != PredicateReview {
		t.Errorf("predicateType = %q, want %q", stmt.PredicateType, PredicateReview)
	}
	if stmt.Signer != "bob@semver-trust.test" {
		t.Errorf("signer = %q, want bob@semver-trust.test", stmt.Signer)
	}
	if len(stmt.Subjects) != 2 ||
		stmt.Subjects[0].Name != in.Subjects[0] ||
		stmt.Subjects[0].Digest["gitCommit"] != in.Subjects[0] {
		t.Errorf("subjects = %+v, want name+gitCommit digest per covered SHA", stmt.Subjects)
	}

	// The payload carries the injected timestamp in RFC 3339 UTC.
	var payload struct {
		Predicate struct {
			Timestamp     string `json:"timestamp"`
			MergeStrategy string `json:"merge_strategy"`
			PullRequest   string `json:"pull_request"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(emission.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Predicate.Timestamp != "2026-01-01T00:00:00Z" {
		t.Errorf("timestamp = %q, want the injected 2026-01-01T00:00:00Z", payload.Predicate.Timestamp)
	}
}

// A commit-signing enrollment (namespaces="git") must NOT verify an
// attestation from the same key: ADR-022's purpose binding, exercised
// against emitted output.
func TestEmitReviewRejectedByGitOnlyEnrollment(t *testing.T) {
	signer := newEmitTestSigner(t)
	emitter, err := NewReviewEmitter(signer, reviewSchemaBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	emission, err := emitter.Emit(validReviewInput())
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := NewVerifier([]sshsig.AllowedSigner{{
		Principals: []string{"bob@semver-trust.test"},
		Namespaces: []string{"git"},
		Key:        signer.PublicKey(),
	}}, map[string][]byte{PredicateReview: reviewSchemaBytes(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(emission.Envelope, emitEpoch); !errors.Is(err, ErrRevokedSigner) {
		t.Errorf("git-only enrollment: err = %v, want ErrRevokedSigner", err)
	}
}

// A payload that does not validate is refused BEFORE signing (signed bytes
// are frozen — fixture plan §6 rider): the error is the schema class, and no
// envelope exists.
func TestEmitReviewRefusesSchemaInvalidBeforeSigning(t *testing.T) {
	emitter, err := NewReviewEmitter(newEmitTestSigner(t), reviewSchemaBytes(t))
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*ReviewInput){
		"bad verdict":        func(in *ReviewInput) { in.Reviewers[0].Verdict = "lgtm" },
		"bad reviewer class": func(in *ReviewInput) { in.Reviewers[0].Class = "robot" },
		"bad merge strategy": func(in *ReviewInput) { in.MergeStrategy = "fast-forward" },
		"empty pull request": func(in *ReviewInput) { in.PullRequest = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := validReviewInput()
			mutate(&in)
			emission, err := emitter.Emit(in)
			if !errors.Is(err, ErrSchemaInvalid) {
				t.Errorf("err = %v, want ErrSchemaInvalid", err)
			}
			if emission.Envelope != nil {
				t.Error("a refused emission still produced envelope bytes")
			}
		})
	}
}

// Structural preconditions fail with their own messages before any schema or
// signing work.
func TestBuildReviewStatementPreconditions(t *testing.T) {
	cases := map[string]func(*ReviewInput){
		"no subjects":  func(in *ReviewInput) { in.Subjects = nil },
		"no reviewers": func(in *ReviewInput) { in.Reviewers = nil },
		"no timestamp": func(in *ReviewInput) { in.Timestamp = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := validReviewInput()
			mutate(&in)
			if _, err := BuildReviewStatement(in); err == nil {
				t.Error("BuildReviewStatement accepted invalid input")
			}
		})
	}
}

// Agent reviewers carry their optional tool/model fields and the §3.3
// independence assertions through to the payload, and it still validates.
func TestEmitReviewAgentReviewerWithIndependence(t *testing.T) {
	emitter, err := NewReviewEmitter(newEmitTestSigner(t), reviewSchemaBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	in := validReviewInput()
	in.Reviewers = []Reviewer{{
		Identity: "reviewer-bot@semver-trust.test",
		Class:    "agent",
		Verdict:  "approved",
		Agent:    "fixture-agent/1.0",
		Model:    "fixture-model-1",
	}}
	in.Independence = &Independence{SeparateExecutionContext: true, DistinctIdentity: true}

	emission, err := emitter.Emit(in)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	var payload struct {
		Predicate struct {
			Reviewers []struct {
				Agent string `json:"agent"`
				Model string `json:"model"`
			} `json:"reviewers"`
			Independence struct {
				SeparateExecutionContext bool `json:"separate_execution_context"`
				DistinctIdentity         bool `json:"distinct_identity"`
			} `json:"independence"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(emission.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Predicate.Reviewers[0].Agent != "fixture-agent/1.0" || payload.Predicate.Reviewers[0].Model != "fixture-model-1" {
		t.Errorf("agent reviewer fields = %+v", payload.Predicate.Reviewers[0])
	}
	if !payload.Predicate.Independence.SeparateExecutionContext || !payload.Predicate.Independence.DistinctIdentity {
		t.Errorf("independence = %+v", payload.Predicate.Independence)
	}
}

// StoreForSubjects files the same envelope under every covered SHA, so
// List(commitSHA) finds it for each commit of the range.
func TestStoreForSubjects(t *testing.T) {
	store := &fakeStore{puts: map[string][][]byte{}}
	envelope := []byte(`{"payloadType":"application/vnd.in-toto+json"}`)
	subjects := []string{"aaaa", "bbbb"}

	refs, err := StoreForSubjects(store, subjects, envelope)
	if err != nil {
		t.Fatalf("StoreForSubjects: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %v, want one per subject", refs)
	}
	for _, s := range subjects {
		if got := store.puts[s]; len(got) != 1 || string(got[0]) != string(envelope) {
			t.Errorf("subject %s: stored %d envelopes", s, len(got))
		}
	}
}

type fakeStore struct{ puts map[string][][]byte }

func (f *fakeStore) Put(subject string, envelope []byte) (string, error) {
	f.puts[subject] = append(f.puts[subject], envelope)
	return "refs/attestations/" + subject + "/fake", nil
}

func (f *fakeStore) List(subject string) ([][]byte, error) { return f.puts[subject], nil }
