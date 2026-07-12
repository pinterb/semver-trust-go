// SPDX-License-Identifier: Apache-2.0

// Package verify orchestrates the spec §10 verification algorithm: given a
// component, a proposed release commit TO, and a previous tag FROM, it walks
// the range, verifies every commit end-to-end, aggregates trust, and emits a
// traceable report. It composes the merged building blocks — internal/vcs
// (range enumeration, signature verification), internal/trust (classification,
// scopes, propagation), internal/policy (the loaded policy), internal/attest
// (review attestations), internal/derive (derivation proofs), and the public
// graph/evidence seams — without reimplementing any of their semantics.
//
// This package implements §10 steps 1–7; the decision and emit steps (8–9)
// are the release command's (GO-042). It is deliberately internal (ADR-011):
// cmd/ stays a thin adapter that injects the verification clock at the process
// boundary and renders what Verify returns.
//
// # Abort semantics (§10)
//
// Verification fails closed. Any commit that cannot be verified end-to-end —
// unsigned, unknown or revoked signer, tampered, an unsupported key family, or
// a stored review attestation that does not verify — aborts the whole run:
// unverifiable is never T0 (§5.2). A meta-path commit below the required level
// aborts outright — not demote, fail (§5.4). Every abort is an *AbortError
// naming the §10 step it failed at, so the one-line reason the CLI prints to
// stderr is traceable to the algorithm.
//
// # The adoption boundary (ADR-026)
//
// A policy MAY declare an adoption boundary ([policy] adoption_boundary): a
// revision before which history is exempt from verification. A first release
// (empty FROM) then anchors at boundary..TO instead of root..TO; ranges with
// an explicit FROM are unaffected. The boundary is policy-pinned — there is
// deliberately no CLI or Options field for it, because a verifier-supplied
// boundary could be moved by whoever runs the verifier — and every
// boundary-anchored report discloses the anchoring in both the human and
// JSON renderings. Pre-boundary commits contribute nothing: no levels, no
// scopes — exempt history makes no claim, which is not the same as T0
// (ADR-008). ADR-008's unverifiable-⇒-abort posture holds unchanged inside
// the verified region.
//
// # Trust-material resolution and precedence (§9)
//
// Three trust-material inputs — the human allowed-signers registry, the GPG
// keyring, and the attestation-signer registry — each resolve the same way: an
// explicit Options path (the CLI flag) wins; otherwise the corresponding §9
// policy field is read from TO's tree ([identity.human] allowed_signers and
// gpg_keyring, [identity] attestation_signers, ADR-022); otherwise the input is
// absent. Reading the default from TO's tree (never the working tree) keeps the
// policy the root of trust: the same commit that pins the policy also pins
// where its trust material lives, and a dirty checkout cannot change either.
// Absence degrades honestly per family — no allowed-signers and no keyring
// aborts (no trust material at all); no attestation registry classifies reviews
// none; no keyring leaves the GPG family fail-closed — while a declared-but-
// unreadable path always aborts.
//
// # A sequencing note on the §5.4 meta-path check
//
// §10 step 1 says to verify the policy file's own history within FROM..TO
// satisfies §5.4 (the meta-path level). That check needs per-commit trust
// levels, which are only assigned in step 3. Rather than verify signatures
// twice, this package loads the policy and records its digest in step 1, then
// runs the §5.4 level check after step 3 classification — when levels exist —
// but reports it as the step-1/§5.4 abort it is. The ordering is an internal
// implementation detail; the observable semantics match §10 exactly.
package verify
