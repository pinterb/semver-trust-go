<!-- SPDX-License-Identifier: Apache-2.0 -->
# Recurring release runbook (v0.10 opt-in chain)

The repeatable cadence for cutting a **v0.10 recurring release chain** — the
authenticated `release/v0.2` predicate behind an out-of-band bootstrap descriptor
(ADR-027/028/029/030). It is the opt-in sibling of the default
[release runbook](release-runbook.md): where that path derives the version from
`--from`, this path derives it from the **authenticated version ancestry** (the
descriptor and the accepted chain head), so the version line and the boundary
disclosure are facts of the chain, not of flag spelling (go#70).

Every step below was exercised end-to-end by the recurring dogfood ceremony —
[history/2026-07-20-recurring-dogfood.md](history/2026-07-20-recurring-dogfood.md)
is that record, with the real transcript. Steps that sign a tag or attestation are
the maintainer's non-delegable accountability acts (specification Principle 2).

## When to use this instead of the default runbook

Use it when you want the authenticated recurring chain: exact intervals
(`P..TO`, not `FROM..TO`), a hash-chained `version_state` per release, and a
version line the verifier derives rather than trusts. The published v0.1.0–v0.2.1
tags use the default `release/v0.1` path; this path starts a new `release/v0.2`
chain (see [Continuing an already-published line](#continuing-an-already-published-line)
for adopting it on a repo that already ships releases).

## Standing notes

- **The bootstrap descriptor is out-of-band.** It is the verifier-supplied v0.10
  authority (ADR-028) and **must live outside the repository** — `--bootstrap-descriptor`
  refuses any path that resolves inside the repo under verification. Author it once
  (§0) and keep it wherever your verifier config lives.
- **`--from` and `--iteration` are not used** in v0.10 mode. The version predecessor
  and the trust iteration are authenticated by the ancestry (§7.5/ADR-029); passing
  them is refused. `--claimed-bump`, `--blast`, and `--repository-digest` still apply.
- **The clock is injected.** One `--verify-time` (RFC3339) is the recorded instant for
  the whole release — bound into both the tag and the attestation (ADR-018); a
  reproducing outsider injects the same instant. Keep it before any signing-key expiry.
- **A pre-release outcome is not a failure.** Under threshold T2, an under-reviewed
  interval demotes to `v<core>-t<level>.<iteration>` — the honest channel, promotable
  later (§4). An *abort* means something is unverifiable — stop and fix it.

## 0. Author the bootstrap descriptor (once, out-of-band)

The descriptor's `policy_digest` and `trust_material` digests must be the **committed
blob bytes at the release commit** (not your working tree) — that is what makes it
authenticate by construction. Compute them straight from git:

```sh
TO=$(git rev-parse main)
pol="sha256:$(git cat-file blob "$TO":.semver-trust/policy.toml | sha256sum | cut -d' ' -f1)"
sig="sha256:$(git cat-file blob "$TO":.semver-trust/allowed_signers | sha256sum | cut -d' ' -f1)"
att="sha256:$(git cat-file blob "$TO":.semver-trust/attestation_signers | sha256sum | cut -d' ' -f1)"
```

Write the JSON **outside the repo** (`version_predecessor: null` starts a new line;
`interval_mode` is `inception` for `root..TO`):

```json
{
  "repository": "repo:you/widget",
  "component": "default",
  "interval_mode": "inception",
  "policy_path": ".semver-trust/policy.toml",
  "policy_digest": "sha256:…",
  "trust_material": {
    ".semver-trust/allowed_signers": "sha256:…",
    ".semver-trust/attestation_signers": "sha256:…"
  },
  "trust_roles": {
    "human_signers": ".semver-trust/allowed_signers",
    "attesters": ".semver-trust/attestation_signers"
  },
  "verification_profile": "semver-trust-verify-json@0.10",
  "clock_profile": "recorded-instant",
  "version_predecessor": null
}
```

The policy **must declare its trust registries in-tree** (`[identity]
attestation_signers`, `[identity.human] allowed_signers`) — v0.10 mode resolves
material from the tree and refuses the `--attestation-signers`/`--gpg-keyring`
overrides (a key-substitution guard, §5.4/ADR-028). Pick a stable
`--repository-digest sha256:<hex>` (the §4.3 repository identity) and reuse it for
every release in the chain.

Sanity-check that the descriptor loads before you sign anything:

```sh
semver-trust verify --repo . --to main \
  --bootstrap-descriptor ../descriptor.json --verify-time <VT>
```

## 1. MANUAL — the genesis release (`release/v0.2` chain head)

```sh
semver-trust release --repo . --to main \
  --bootstrap-descriptor ../descriptor.json \
  --predicate v0.2 --repository-digest sha256:<hex> \
  --claimed-bump <patch|minor|major> --blast <low|moderate|high> \
  --tag-key ~/.ssh/semver-trust-attest --attest-key ~/.ssh/semver-trust-attest \
  --verify-time <VT>
```

`--dry-run` first (keyless — writes nothing). A clean genesis:

```text
  channel:        clean
  version:        v0.1.0
  version line:   new line (authenticated null predecessor, §7.5/ADR-029)
tag v0.1.0 -> … (signed annotated, SSHSIG namespace "git")
release attestation https://semver-trust.dev/release/v0.2
```

This stores the genesis `release/v0.2` under `refs/attestations/<commit>/…` **and**
`refs/attestations/v0.1.0/…` — the accepted chain head.

## 2. MANUAL — a recurring advance

Land new commits, then run the **same command, still no `--from`**. Recurrence is
auto-detected from the stored chain head + its tag:

```text
  version:        v0.2.0
  version line:   continues v0.1.0 (authenticated, §7.5/ADR-029)
```

The successor binds `version_state.predecessor = v0.1.0`, `interval.mode = recurring`
(interval `v0.1.0..TO`), the predecessor attestation, and `prior_state.digest ==` the
predecessor's `resulting_state.digest` — the ADR-036 hash-chain link. An under-reviewed
interval demotes: e.g. an unreviewed agent commit lands `v0.3.0-t0.1` at effective T0.

## 3. MANUAL — recut an unpromoted prerelease

When the head is an unpromoted prerelease and more source lands for the *same* target,
re-cut it (same core, next iteration) instead of advancing the core:

```sh
semver-trust release --repo . --to main --action recut \
  --bootstrap-descriptor ../descriptor.json --predicate v0.2 \
  --repository-digest sha256:<hex> --claimed-bump <…> --blast <…> \
  --tag-key … --attest-key … --verify-time <VT>
```

→ `v0.3.0-t0.2` (`action=recut`, target core preserved, iteration 2, source lineage
grows so skipped prereleases can't launder trust). `--action recut` requires
`--predicate v0.2` and an accepted prerelease predecessor.

## 4. MANUAL — promote/supersede a prerelease to clean

Attest the new evidence (a review over the prerelease's range, lifting agent commits
to T2), then `promote` re-decides the **identical commit** to the clean channel:

```sh
semver-trust attest review --repo . --from <prev-clean> --to HEAD \
  --reviewer you@example.com --verdict approved \
  --pr <url> --key ~/.ssh/semver-trust-attest --store

semver-trust promote --repo . --tag v0.3.0-t0.2 \
  --bootstrap-descriptor ../descriptor.json --repository-digest sha256:<hex> \
  --tag-key ~/.ssh/semver-trust-attest --attest-key ~/.ssh/semver-trust-attest \
  --verify-time <VT>
```

```text
  clean tag:      v0.3.0 -> <same commit as v0.3.0-t0.2>
  channel:        clean
  supersedes:     refs/attestations/<commit>/…
release attestation https://semver-trust.dev/release/v0.2 (supersedes the prior decision, §8.1)
```

The clean tag lands on the prerelease's SHA; the new attestation binds
`decision.supersedes` to the superseded envelope and chains its `version_state` to it.
If the evidence hasn't changed the decision, `promote` refuses — it is never a re-cut.

## 5. Verify the chain, and reproduce it

```sh
semver-trust verify --repo . --to main --bootstrap-descriptor ../descriptor.json --verify-time <VT>
```

This discovers the accepted head, walks the complete chain genesis→head reproducing
every `resulting_state` digest and `prior_state` link, and classifies only the
post-head interval under the **predecessor** authority.

> **Verifying *at* a release's own commit is `promotion_required` by design.**
> `verify --to <the head tag>` computes an empty interval (`P..P`) and aborts
> `promotion_required` (§5.2/ADR-027) — *after* the chain reader has validated the whole
> chain. That abort at a release's own tag means "the chain is valid and this is the
> head." A genuinely broken chain aborts differently (an ambiguous-head / broken-link
> error at §10 step 1). Verify the chain from a *later* commit, or read the release's
> own recorded decision from its attestation.

**Outsider reproduction** — the point of the whole exercise: a fresh clone plus the
out-of-band descriptor re-derives the decision. The descriptor *authenticates* the
in-tree trust material rather than trusting it because it sits in the tree (spec#37):

```sh
git clone <remote> /tmp/fresh && cd /tmp/fresh
git fetch origin 'refs/attestations/*:refs/attestations/*'
semver-trust verify --repo . --to main --bootstrap-descriptor <descriptor> --verify-time <VT>
```

## Continuing an already-published line

To adopt this chain on a repo that already ships releases (e.g. past `v0.2.1`), set the
descriptor's `version_predecessor` to that tag's binding instead of `null`, so the
authenticated line continues rather than restarting:

```json
"version_predecessor": {
  "tag": "v0.2.1",
  "ref_oid": "<the tag object's SHA>",
  "commit_oid": "<the peeled commit SHA>"
}
```

The first `release/v0.2` then continues the line (e.g. `v0.2.1` → `v0.3.0`) instead of
minting `v0.1.0`. This is the path a live repository takes when transitioning from the
default `release/v0.1` chain; the CI publish gate must learn the v0.10 verify path first
(see `.github/workflows/release.yml`).

**This repository did exactly this.** On 2026-07-20 it continued its own published line
`v0.2.1` → `v0.3.0` — a signed `release/v0.2` genesis, CI-verified via `verify
--chain-head` and reproduced by an outsider at effective **T2**. See the [v0.10 transition
record](history/2026-07-20-v0.10-transition.md) for the full ceremony, including the
descriptor round-trip gotcha (a GitHub Actions variable strips a trailing newline, so bind
the genesis to the canonical no-trailing-newline descriptor and verify the round-trip
before pushing the tag).

## Out of scope here

Two-stage policy rotation (rotating a signing key across a release boundary) and the
attestation-only supersede outcomes (late supersession after the line advanced, demotion,
corrective-floor) are wired and conformance-tested but not part of this cadence; they are
documented where the code lands.
