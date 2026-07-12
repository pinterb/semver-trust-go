<!-- SPDX-License-Identifier: Apache-2.0 -->
# semver-trust-verify (GitHub Action)

Composite action running `semver-trust verify` — SemVer-Trust spec §10
steps 1–7 — against a repository range. It builds the verifier from this
repository at the pinned action ref (no prebuilt binaries to trust), writes
a job-summary section tracing the §10 steps, and emits a
[shields.io endpoint](https://shields.io/badges/endpoint-badge) `badge.json`
uploaded as a workflow artifact. This is the ADR-017 demand-side consumer:
the zero-friction way to *see* a repository's trust level.

## Honesty contract

A verification abort is reported as **unverifiable**, naming the failing
§10 step. It is never rendered as a pass (P4; unverifiable is never T0,
spec §5.2). `informational: 'true'` only controls whether the *job* fails —
the summary and badge always tell the truth.

This repository itself currently has no `.semver-trust/policy.toml` and its
pre-ADR-023 history contains web-flow merges, so its own verify honestly
aborts at §10 step 1. The `self-verify` job in
[`semver-trust-verify.yml`](../../workflows/semver-trust-verify.yml) runs
informationally until D3/GO-061 land a policy; the `fixture-verify` job
proves the verified path end-to-end against the deterministic release
fixture.

## Usage

Informational (report honestly, never fail the job):

```yaml
- uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0  # v7.0.0
  with:
    fetch-depth: 0  # verify walks the release range's history
- uses: semver-trust/semver-trust-go/.github/actions/semver-trust-verify@main
  with:
    informational: 'true'
```

Enforced, with pinned range, signers, and clock (the fixture e2e):

```yaml
- uses: semver-trust/semver-trust-go/.github/actions/semver-trust-verify@main
  with:
    repo-path: ${{ runner.temp }}/fixtures/release
    from: v0.1.0
    to: main
    allowed-signers: conformance/vendor/crypto/allowed_signers
    verify-time: '2026-01-01T00:00:00Z'
    informational: 'false'
```

## Inputs

| input | default | meaning |
| --- | --- | --- |
| `repo-path` | `.` | repository to verify (`verify --repo`) |
| `from` | `''` | previous release tag; empty = first release (root..TO) |
| `to` | `HEAD` | proposed release commit (revision) |
| `policy` | `.semver-trust/policy.toml` | policy file path within TO's tree |
| `allowed-signers` | `''` | filesystem allowed-signers override; empty resolves the policy's in-tree path |
| `verify-time` | `''` | verification instant (RFC3339); empty = now |
| `informational` | `'false'` | when `'true'`, an abort does not fail the job (still reported honestly) |
| `badge-artifact` | `semver-trust-badge` | artifact name for `badge.json`; override for multiple runs per workflow |

## Outputs

| output | meaning |
| --- | --- |
| `outcome` | `verified` \| `aborted` |
| `effective` | effective trust level (e.g. `T2`) when verified; empty on abort |
| `badge-path` | filesystem path of the generated `badge.json` |

## Badge

`badge.json` follows the shields.io endpoint schema:

```json
{"schemaVersion": 1, "label": "SemVer-Trust", "message": "T2 ✓", "color": "yellowgreen"}
```

Color maps the *level* — accountability, not pass/fail (ADR-019) — and
grey means no claim can be made at all (ADR-008):

| result | message | color |
| --- | --- | --- |
| verified, T3 | `T3 ✓` | green |
| verified, T2 | `T2 ✓` | yellowgreen |
| verified, T1 | `T1 ✓` | orange |
| verified, T0 | `T0 ✓` | red |
| abort | `unverifiable` | lightgrey |

Render any endpoint document via
`https://img.shields.io/endpoint?url=<raw-url-to-badge.json>`.

### Test README badge

A static sample endpoint document is committed next to this README as
[`sample-badge.json`](./sample-badge.json), so the pattern renders today:

![SemVer-Trust](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsemver-trust%2Fsemver-trust-go%2Fmain%2F.github%2Factions%2Fsemver-trust-verify%2Fsample-badge.json)

```markdown
![SemVer-Trust](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsemver-trust%2Fsemver-trust-go%2Fmain%2F.github%2Factions%2Fsemver-trust-verify%2Fsample-badge.json)
```

The sample is a *test fixture for the rendering path* (it shows the
ADR-017 "SemVer-Trust: T2 ✓" shape); it is not a claim about this
repository. Live badges come from the `badge.json` this action uploads as
a workflow artifact — or, once this repo dogfoods its own releases
(GO-061), from a published endpoint updated on each verified release, at
which point the README badge switches to live.
