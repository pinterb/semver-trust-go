<!-- SPDX-License-Identifier: Apache-2.0 -->
# Reading verify output

`semver-trust verify` walks a release range through the spec §10 pipeline and
prints one section per step. This page reads a real report — every excerpt
below was produced by this repository's own verification — and covers the one
distinction people misread most: an *abort* is not a *low trust level*.

## The shape of a passing report

Header, then steps. From this repository's `v0.1.0..v0.2.0` pre-flight:

```text
verify .  (v0.1.0..d00920566c75440f652f94f20ea7850d77d71b9f)
TO commit: d00920566c75440f652f94f20ea7850d77d71b9f
verify-time: 2026-07-12T04:15:00Z

[§10 step 1] policy
  path:      .semver-trust/policy.toml
  digest:    sha256:e085c25cb495b9cc7c20d569e62a4540ef09b545439ed7ab074ee56f5547ed25
  threshold: T2   strategy: demote   graph: none
  meta-paths (T2 required): .semver-trust/**, ... — check PASSED
```

Step 1 pins *which rules produced this decision*: the policy digest freezes
the exact policy text, and the meta-path check confirms every commit touching
guarded files individually met the required level.

```text
[§10 steps 2–3] commits
  SHA      LEVEL  AUTHORSHIP  REVIEW          SIGNER
  d009205  T2     ambiguous   human_distinct  noreply@github.com (merge)
  5348847  T2     agent       human_distinct  brad.pinter@gmail.com
  ...
```

One row per commit: its verified signer, its authorship class (from signature
identity + [Provenance trailer](trailers.md)), its review class (from stored
[attestations](attestation-refs.md)), and the per-commit level the spec §3.2
matrix assigns. This table is where you find *your* commit and see exactly how
it was classified — and where a forgotten trailer or an unenrolled reviewer
becomes visible.

```text
[§10 step 5] own trust (per scope)
  default: T2  (commits: 91e591d, 5348847, ...)

[§10 step 6] effective trust (adapter: none)
  default: own T2 -> effective T2 (floor source: default) <- target
```

**Own** trust is the weakest link among a scope's commits — one T0 commit
floors its whole scope. **Effective** trust additionally floors each scope by
everything it depends on (with a workspace graph; with `adapter: none` there
is one scope and the two are equal). The `floor source` names which scope is
responsible for the floor — when your level is lower than you expected, this
is the field that says *why*, and the commit list in step 5 says *which
commits*.

```text
[§10 step 7] evidence
  changed files: 53   changed LOC: unavailable
  semantic floor: minor (from declared_intent)
  blast score: unavailable
```

Evidence the decision consumes. `unavailable` is deliberate: anything the
configured providers cannot compute is reported as missing, never fabricated
(spec §1.1).

When run through `release`, two more steps follow: the §6.4 decision (channel
and version) and the emitted tag + attestation.

### Clean-channel eligibility

After effective trust, `verify` prints one informational line comparing it to
the policy threshold. The threshold is a **release-decision** gate (spec
repository ADR-032), so `verify` *reports* eligibility without itself gating:

```text
  clean channel: threshold met (effective T2 >= threshold T2; §6.4 blast/differ still applies at release)
```

Below the threshold it reads `clean channel: below threshold (effective T1 <
threshold T2) - unavailable regardless of blast/differ (§6.2/ADR-032)`. "Met"
means only that the accountability gate is cleared — not that the release will
be clean; the §6.4 blast/differ table is a separate release-time factor.

## Abort vs T0 — the distinction that matters

**T0 is a verified statement**: every signature checked out, and the evidence
shows no accountable human. It is a level, it is honest, and a T0 release can
ship (on the pre-release channel) and later be
[promoted](attestation-refs.md#supersession-not-mutation).

**An abort is the refusal to make any statement.** Something in the range
could not be verified — so the pipeline stops with a one-line reason naming
the failing step, and no level exists at all. Unverifiable is never T0
(spec §5.2); rendering a broken signature as "zero trust" would let attackers
*choose* T0 by breaking things.

Real aborts, and what to do about them:

```text
Error: §10 step 3 (verify signature): verify 5348847...: OpenPGP: signing key is not an allowed signer
```

A commit is signed by a key that is in no registry at the range tip. Enroll
the key ([trust material](trust-material.md)) — or, in legacy adoption, this
is the [key-archaeology loop](../guides/adopt-legacy-github.md#2-key-archaeology) telling you
which key to hunt next.

```text
Error: §10 step 1 (load policy): gpg-keyring: pgp: keyring contains no keys
```

Trust-shaped-but-malformed input fails closed at load: an empty or corrupt
registry aborts before any commit is examined. Fix the file, don't work
around it.

```text
Error: §10 step 1 (load policy): policy file ".semver-trust/policy.toml" not found in main's tree
```

The target commit's tree has no policy — remember that material is read from
the *tree being verified*, not from your working directory.

## The boundary disclosure

When a policy declares an [adoption boundary](policy.md) and a first release
verifies from it, the report says so — the reader must never mistake
"verified since the boundary" for "verified since inception":

```text
range: v0-import..main (FROM is the adoption boundary declared in policy — history before it is exempt and makes no claim; ADR-026)
```

## `--json`

Everything above, machine-readable: `verify --json` emits the full report —
policy digest, per-commit provenance vector, per-scope floors with sources,
evidence, and (via `release`) the decision block. CI integrations read
`.propagation.components[].effective` for badge and gate logic; the committed
report shape is versioned with the tool.

When a **bootstrap descriptor** is supplied — the opt-in v0.10 path
(`--bootstrap-descriptor`, [the policy file](policy.md)) — the `--json` report
additionally carries the authenticated **policy state** (`policy_state`: active
and candidate policy plus trust roots, and the transition authority; spec
repository ADR-028). The authenticated **version state** (the version predecessor
and its ADR-029/036 resulting-state digest) is *not* a verify field — it is bound
by the `release/v0.2` predicate the release path emits; the accepted chain head
`verify` uses to detect recurrence is an in-process handoff, not serialized.
`policy_state` is JSON-only; the human table stops at step 7.

## See also

- [Trailers](trailers.md) — the authorship half of the commit table.
- [Trust material](trust-material.md) — fixing unknown-signer aborts.
- [The policy file](policy.md) — thresholds, meta-paths, and the boundary.
