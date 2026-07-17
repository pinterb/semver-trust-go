<!-- SPDX-License-Identifier: Apache-2.0 -->
# Conformance coverage

This implementation vendors the SemVer-Trust conformance vectors digest-pinned
(ADR-021; see [`conformance/`](../conformance/) and
[architecture.md](architecture.md)). `semver-trust --version` reports the spec
draft version of the vendored vectors — currently **v0.10**.

A single draft version pins the *provenance* of the vendored vectors; it is not
a claim that every v0.10 protocol capability is implemented. The spec's draft
v0.10 introduced the audit-hardening model (ADR-027 through ADR-035) as several
large new vector suites. This table states which suites the implementation
**enforces** (loads and passes). Every vendored suite is now enforced; the
remaining work is wiring these ported evaluators into the production verify
pipeline (tracked in
[semver-trust-go#76](https://github.com/semver-trust/semver-trust-go/issues/76)).

| Suite | Spec area | Status |
|---|---|---|
| levels | §3.2 per-commit classification | **enforced** |
| precedence | §7.1 trust-version ordering | **enforced** |
| grammar | §7.1 trust-version parsing | **enforced** |
| aggregation | §5.1–5.2 scope floors (derivation non-authoritative, ADR-033) | **enforced** |
| propagation | §5.3 transitive propagation | **enforced** |
| decision | §6.2–6.4 threshold gate + decision table (ADR-032) | **enforced** |
| signature | §4.2 / §10 commit-signature verification | **enforced** |
| attestation | §8.2 DSSE verify (v0.1 in production; v0.1/v0.2 **schema** validation in the conformance harness) | **enforced** |
| review-qualification | §4.3 qualified review + canonical actors (ADR-031) | **enforced** |
| range | §5.2 exact release intervals (ADR-027) | **enforced** |
| policy-transition | §5.4 bootstrap + policy transitions (ADR-028) | **enforced** |
| version-ancestry | §7.5 authenticated version state (ADR-029) | **enforced** |
| source-evidence | §8.3 SLSA Source profiles (ADR-035) | **enforced** |
| publishing-profile | §7.4 ecosystem routing (ADR-034) | **enforced** |
| predicate-v0.2 | §8.1 release/v0.2 payload validation (ADR-030) | **enforced** |
| version-state-canonicalization | §8.1 version-state digest profile: JCS + SHA-256, hash-chained (ADR-036) | **enforced** |

**What "review-qualification enforced" covers today:** the ADR-031 qualification
logic (`trust.QualifyReview`) — approved-verdict, active-at-merge, final-revision
or final-diff binding, canonical-actor distinctness, and agent independence — is
implemented and passes the suite. The **production** verify path still consumes
review/v0.1 attestations, where the verdict half is already enforced (#78) and
distinctness uses raw signer identity; migrating it to build the qualified facts
from review/v0.2 predicates and the policy actor map is tracked in #76.

**What "policy-transition enforced" covers today:** the §5.4/ADR-028
transition logic (`policy.SelectPolicyTransition`) — active authority from an
authenticated bootstrap descriptor or the accepted predecessor chain head,
candidate-activates-next, no self-enrollment, no lowered guardrails, mandatory
meta-path coverage, and under-level meta-commit rejection — is implemented and
passes the suite over abstract policy state. The **production** verify path
still loads the policy from TO (the pre-ADR-028 model); feeding
`SelectPolicyTransition` real bootstrap/predecessor state is tracked in #76.

**What "version-ancestry enforced" covers today:** the §7.5/ADR-029
version-state logic (`version.SelectVersionAncestry`) — bootstrap/predecessor
baseline selection, advance/recut/supersede actions, corrective floors,
target-lineage re-evaluation, and derived target core / iteration / exact tag /
head-advance — is implemented and passes the suite over abstract chain state.
This is the resolution of the go#70 dogfood finding (the version line and the
adoption-boundary disclosure become independent authenticated facts, not a
function of `--from` spelling). The **production** release path still derives
versions from `FROM`; wiring `SelectVersionAncestry` into it — which is what
actually closes go#70 — is tracked in #76.

**What "publishing-profile enforced" covers today:** the §7.4/ADR-034
resolver-routing claim evaluation (`publish.SelectPublishingProfile`) — registry
routing is never a trust anchor; same-source promotion proves artifact equality
only under a reproducible-build profile with matching digests; and each
ecosystem's default resolution (go module query, npm `latest` dist-tag, cargo
default dependency, pypi rc projection) must hide or defer a trust pre-release
rather than serve it as an ordinary install. It is a claim-constraint gate over
abstract resolver facts: it decides whether a routing/promotion claim is
*permitted*, not how a real registry resolves. PyPI projection is deferred by
design (the profile only rejects a non-injective rc collision). No production
path feeds it real registry state; wiring is tracked in #76.

**What "source-evidence enforced" covers today:** the §8.3/ADR-035
source-evidence profile evaluation (`source.SelectSourceEvidence`) — repository/
resource binding, subject-revision matching, allowed-digest-algorithm and
trusted-issuer authorization, `replay` vs `trusted_issuer` verification mode,
freshness, hidden-demotion detection, and issuer equivocation — is implemented
and passes the suite over abstract VSA / source-provenance facts. This is the
consumption gate only: a signed Verification Summary is a summary from an
issuer, so the profile decides whether to replay the underlying provenance or
explicitly trust the issuer before its facts are used. It does **not** map SLSA
Source levels to T-levels (ADR-035 rejects that), and no production path yet
feeds it real VSAs — wiring source-evidence profiles into the verify pipeline is
tracked in #76.

**What "range enforced" covers today:** the §5.2/ADR-027 interval-selection
logic (`vcs.SelectInterval`) — inception, adoption (bootstrap-pinned boundary,
included, parent history excluded), and recurring (anchored to the accepted
predecessor chain head), with every caller-selected / skipped / moved /
mismatched abort — is implemented and passes the suite over abstract commit
graphs. The **production** verify path still uses the existing two-dot range
walk; feeding `SelectInterval` real git reachability and accepted-predecessor
attestations is tracked in #76.

**What "attestation enforced" covers today:** the `attest.Verifier` is generic —
it verifies signatures against the injected attestation-signer registry and
validates each envelope against whichever predicate JSON Schemas it is given.
The **production** verify path (`internal/verify`) injects only release/v0.1 and
review/v0.1 schemas. The **conformance harness** additionally injects
release/v0.2 and review/v0.2, so the two v0.2 successor envelopes are exercised
at the schema + signature level. Neither path yet consumes the full v0.4+
release semantics the v0.2 predicate carries (interval, policy-state,
version-state); that lands with the range / policy-transition / version-ancestry
suites above.

**What "predicate-v0.2 enforced" covers today:** the §8.1/ADR-030 release/v0.2
and review/v0.2 predicate payloads validate against their vendored JSON Schemas
through `attest.Verifier.ValidatePayload` — the schema half of `Verify`, exposed
so a well-formed but schema-invalid payload can be exercised without a
signature. Payloads flagged with a source-evidence extension are additionally
checked for structural binding (`attest.SourceEvidenceExtensionBound`, §8.3/
ADR-035): the extension's revision and resource must match the release's own
interval and repository, and its mode/profile/issuer-roots/evidence/freshness
must be populated. This is payload-shape validation; the production emit/verify
paths still center on release/v0.1.

Every vendored suite is now enforced. What remains is **production wiring** —
feeding these ported evaluators from the live verify pipeline rather than the
abstract conformance facts they are exercised against today — tracked in #76.
