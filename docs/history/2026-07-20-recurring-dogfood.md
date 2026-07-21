<!-- SPDX-License-Identifier: Apache-2.0 -->
# Recurring dogfood ceremony — 2026-07-20

The record of the first end-to-end run of the v0.10 recurring release chain
(#76). It proves the wired chain — genesis → recurring advance → recut →
promote/supersede — holds as a real operator ceremony with real crypto,
verify-time discipline, and outsider reproduction, not only as unit tests. The
[recurring release runbook](../recurring-release-runbook.md) is the living
process this run established.

> **This was a disposable demonstration, not a release of `semver-trust-go`.**
> It ran in a throwaway scratch repository with throwaway SSH keys — nothing was
> signed with the maintainer's key and no `release/v0.2` attestation (a v0.10
> recurring chain) has been published for this repository. The canonical repo still
> ships the default `release/v0.1` chain — SemVer tags `v0.1.0`–`v0.2.1`, each with
> a `release/v0.1` attestation. The point was to exercise and document the recurring
> ceremony before adopting it here (see the runbook's *Continuing an
> already-published line*).
>
> *Update, later that day:* the canonical repo has since adopted the v0.10 chain for
> real — `v0.2.1` → `v0.3.0`, a maintainer-signed `release/v0.2` genesis — see the
> [v0.10 transition record](2026-07-20-v0.10-transition.md). This demo remained a
> throwaway; the real transition was a separate ceremony.

## What it exercised

A purpose-built repo mirroring this repository's policy shape — T2/demote, a single
`default` component, in-tree `allowed_signers`/`attestation_signers`, `[trailers]
require = true` — with SSH commit signing and a distinct SSH attestation key
(ADR-022). An out-of-band bootstrap descriptor (`version_predecessor: null`,
`interval_mode: inception`) authored by the deterministic digest recipe in the
runbook. A single injected instant (`--verify-time 2026-07-20T00:00:00Z`).

## The chain it produced

| Tag | Action | Channel | Effective | Notes |
|---|---|---|---|---|
| `v0.1.0` | advance (genesis) | clean | T2 | new authenticated line, `version_predecessor: null` |
| `v0.2.0` | advance | clean | T2 | `prior_state` reproduces the genesis `resulting_state` (ADR-036 link) |
| `v0.3.0-t0.1` | advance | pre-release | T0 | unreviewed agent commit floors the interval → demote |
| `v0.3.0-t0.2` | recut | pre-release | T0 | same core, iteration 2, source lineage grows |
| `v0.3.0` | supersede | clean | T2 | promoted onto `v0.3.0-t0.2`'s identical SHA; supersedes it |

All five are `https://semver-trust.dev/release/v0.2` attestations, stored under both
the commit and the tag.

## Transcript (curated; keys shown as `~/.ssh/…`)

```console
$ semver-trust release --repo . --to main --bootstrap-descriptor ../descriptor.json \
    --predicate v0.2 --repository-digest sha256:<hex> --claimed-bump minor --blast low \
    --verify-time 2026-07-20T00:00:00Z \
    --tag-key ~/.ssh/demo-attest --attest-key ~/.ssh/demo-attest
  channel:        clean
  version:        v0.1.0
  version line:   new line (authenticated null predecessor, §7.5/ADR-029)
tag v0.1.0 -> … (signed annotated, SSHSIG namespace "git")
release attestation https://semver-trust.dev/release/v0.2

# ... a new human commit ...
$ semver-trust release … (same flags, no --from)
  version:        v0.2.0
  version line:   continues v0.1.0 (authenticated, §7.5/ADR-029)

# ... a new UNREVIEWED agent commit ...
$ semver-trust release … (same flags)
  channel:        prerelease
  version:        v0.3.0-t0.1
  effective:      T0 (own T0)

# ... more agent source ...
$ semver-trust release … --action recut
  version:        v0.3.0-t0.2
  version line:   continues v0.3.0-t0.1 (authenticated, §7.5/ADR-029)

$ semver-trust attest review --from v0.2.0 --to HEAD --reviewer … --verdict approved --key ~/.ssh/demo-attest --store
$ semver-trust promote --repo . --tag v0.3.0-t0.2 --bootstrap-descriptor ../descriptor.json \
    --repository-digest sha256:<hex> --verify-time 2026-07-20T00:00:00Z \
    --tag-key ~/.ssh/demo-attest --attest-key ~/.ssh/demo-attest
  clean tag:      v0.3.0 -> <same commit as v0.3.0-t0.2>
  channel:        clean
  effective:      T2 (own T2)
  supersedes:     refs/attestations/<commit>/…
release attestation https://semver-trust.dev/release/v0.2 (supersedes the prior decision, §8.1)
```

## Whole-chain verify and reproduction

```console
# Verifying AT the head's own commit is promotion_required by design:
$ semver-trust verify --to v0.3.0 --bootstrap-descriptor ../descriptor.json --verify-time 2026-07-20T00:00:00Z
Error: §10 step 2 (enumerate commits): authenticated release interval refused (promotion_required, §5.2/ADR-027)

# From a later commit, verify walks the whole chain genesis→head:
$ semver-trust verify --to main --bootstrap-descriptor ../descriptor.json --verify-time … --json
  accepted chain head (from): v0.3.0 | policy authority: predecessor | interval commits: 1

# Outsider reproduction — a fresh clone + the out-of-band descriptor:
$ git clone <repo> /tmp/fresh && cd /tmp/fresh
$ git fetch origin 'refs/attestations/*:refs/attestations/*'
$ semver-trust verify --repo . --to main --bootstrap-descriptor <descriptor> --verify-time …
  reproduced: head v0.3.0 | effective T2 | clean-channel met: True   (exit 0)
```

## Findings carried forward

- **`promotion_required` at a release's own tag is the chain-valid signal.** The chain
  reader validates the complete chain genesis→head *before* the interval check, so
  `verify --to <head tag>` aborting `promotion_required` (§10 step 2) means the chain is
  valid and the tag is the head; a broken chain aborts differently (an ambiguous-head /
  broken-link error at §10 step 1). This shaped the CI verify path (`.github/workflows/release.yml`).
- **The out-of-band descriptor authenticates the in-tree material.** Reproduction needs a
  fresh clone *plus* the descriptor supplied from outside it — the descriptor is what makes
  the in-tree policy/registries trustworthy rather than trusted-because-present (spec#37).
