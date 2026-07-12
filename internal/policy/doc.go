// SPDX-License-Identifier: Apache-2.0

// Package policy loads and validates the SemVer-Trust policy file
// (.semver-trust/policy.toml, spec §9): scopes and their blast-radius
// weights, meta-paths, derivation rules, identity maps, the trust threshold,
// and the enforcement strategy.
//
// The configuration is the root of trust (§5.4, ADR-007): the policy file
// can reclassify anything, so the loader is strict. Unknown keys are errors,
// not warnings — a misspelled key silently ignored would be a hole in the
// root of trust. Enumerated values (threshold, strategy, weights, graph
// adapter, policy version) reject anything outside their §9 vocabulary for
// the same reason: unknown values mean unknown semantics.
//
// Three keys are optional and absent by default (spec §9, adopted in the
// v0.3 pass): [policy] adoption_boundary (ADR-026) is policy-pinned on
// purpose — see Policy.AdoptionBoundary; [identity.human] gpg_keyring and
// [identity] attestation_signers (ADR-022) name in-tree trust-material paths
// that the verifier MAY default its --gpg-keyring / --attestation-signers
// from when those flags are absent (an explicit flag overrides). Declared
// but empty, any of the three is a rejected declaration, not a no-op: an
// empty path in the root of trust is a typo, never a silent "none".
//
// Parse also records the SHA-256 digest of the raw policy bytes, the value
// the verification algorithm pins in the release attestation (§8.1
// decision.policy.digest, §10 step 1).
//
// Loading is pure: bytes in, value out. Verifying that the policy file's own
// history satisfies the meta-path level (§5.4) is the §10 step 1 abort
// check, which lives with the commit-walk machinery, not here.
package policy
