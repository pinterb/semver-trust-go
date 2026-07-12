// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/json"
	"time"

	"github.com/semver-trust/semver-trust-go/internal/attest"
	"github.com/semver-trust/semver-trust-go/internal/trust"
)

// reviewPredicate is the subset of the §4.3 review predicate classification
// consumes: the first reviewer's verified identity and class, and the
// asserted separate-execution-context flag (§3.3 condition 1).
type reviewPredicate struct {
	Predicate struct {
		Reviewers []struct {
			Identity string `json:"identity"`
			Class    string `json:"class"`
		} `json:"reviewers"`
		Independence *struct {
			SeparateExecutionContext bool `json:"separate_execution_context"`
		} `json:"independence"`
	} `json:"predicate"`
}

// reviewResolution is resolveReview's outcome: the classification facts, the
// storage ref of the consumed attestation (the §8.1 review-attestation
// reference; empty when none was consumed), and the honest-degradation note.
type reviewResolution struct {
	facts *trust.ReviewFacts
	ref   string
	note  string
}

// resolveReview locates and verifies the review attestation covering a commit
// (§10 step 3, §4.3). Its three outcomes are deliberate:
//
//   - No stored envelopes → no review (nil facts).
//   - Envelopes stored but no attestation-signer registry given → they cannot
//     be verified, so review classifies none — honest degradation (§4.3). The
//     returned note records that a review was present but unverifiable, so the
//     degradation is visible rather than silent.
//   - Envelopes stored and a registry given → each is verified; any that fails
//     to verify aborts (a stored attestation that does not verify is a
//     fail-closed stop, §8.2), and the first verified review predicate whose
//     subject covers the commit supplies the review facts and is recorded as
//     the consumed attestation ref.
//
// The author identity threaded in is the commit's verified signer principal,
// used for the §3.2/§3.3 distinct-identity tests.
func resolveReview(store attest.GitRefStore, v *attest.Verifier, sha, authorIdentity string, at time.Time) (reviewResolution, error) {
	envelopes, err := store.List(sha)
	if err != nil {
		return reviewResolution{}, err
	}
	if len(envelopes) == 0 {
		return reviewResolution{}, nil
	}
	if v == nil {
		return reviewResolution{
			note: "review attestation present but unverifiable (no --attestation-signers); classified none",
		}, nil
	}

	for _, env := range envelopes {
		stmt, err := v.Verify(env, at)
		if err != nil {
			return reviewResolution{}, err // a stored attestation that fails verification aborts (§8.2)
		}
		if stmt.PredicateType != attest.PredicateReview {
			continue // e.g. a release attestation filed under the commit — not a review
		}
		if !subjectCovers(stmt.Subjects, sha) {
			continue
		}
		facts, err := reviewFacts(stmt, authorIdentity)
		if err != nil {
			return reviewResolution{}, err
		}
		if facts == nil {
			continue
		}
		return reviewResolution{facts: facts, ref: attest.EnvelopeRef(sha, env)}, nil
	}
	return reviewResolution{}, nil
}

// reviewFacts builds the trust.ReviewFacts from a verified review statement.
// The first reviewer is authoritative for the scalar classification (§3.2 maps
// a single review class); a signed, verified attestation sets SignedAttestation.
func reviewFacts(stmt attest.Statement, authorIdentity string) (*trust.ReviewFacts, error) {
	var rp reviewPredicate
	if err := json.Unmarshal(stmt.Payload, &rp); err != nil {
		return nil, err
	}
	if len(rp.Predicate.Reviewers) == 0 {
		return nil, nil
	}
	reviewer := rp.Predicate.Reviewers[0]
	class := trust.IdentityHuman
	if reviewer.Class == "agent" {
		class = trust.IdentityAgent
	}
	separate := rp.Predicate.Independence != nil && rp.Predicate.Independence.SeparateExecutionContext
	return &trust.ReviewFacts{
		Reviewer:          class,
		ReviewerIdentity:  reviewer.Identity,
		SignerIdentity:    authorIdentity,
		SeparateContext:   separate,
		SignedAttestation: true,
	}, nil
}

// subjectCovers reports whether an attestation's subjects bind the commit SHA
// (§8.2: verifiers validate subject digests, not just where the attestation
// was fetched from). A subject matches by name or by any digest value equal to
// the commit hash.
func subjectCovers(subjects []attest.Subject, sha string) bool {
	for _, s := range subjects {
		if s.Name == sha {
			return true
		}
		for _, digest := range s.Digest {
			if digest == sha {
				return true
			}
		}
	}
	return false
}
