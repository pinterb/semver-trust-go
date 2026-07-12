<!-- SPDX-License-Identifier: Apache-2.0 -->
# Release runbook

The repeatable cadence for cutting a trust-tagged release of semver-trust-go
with its own tooling. This is the **living process**; [history/first-release.md](history/first-release.md)
is the historical record of the very first (`v0.1.0`) ceremony. Steps marked
**MANUAL** are the maintainer's accountability acts and cannot be delegated —
signing an attestation asserts *you stand behind the code* (specification
Principle 2); everything else is scripted or already committed.

## Standing notes

- **Trust material is committed** under `.semver-trust/` and the policy names
  its own material (spec §9), so the commands below run flag-free against the
  target commit's tree; an explicit flag still overrides for out-of-band
  material. Formats and semantics:
  [reference/trust-material.md](reference/trust-material.md) and
  [reference/policy.md](reference/policy.md).
- **The clock is injected, and it matters.** The maintainer's 2026-07 temporary
  key expires **2026-08-01**, so any verification instant for history signed by
  it must predate the expiry. Do not use the wall clock for reproduction: the
  release attestation *records* the instant it verified at (`predicate.timestamp`),
  and a reproducing outsider injects **that** instant (ADR-018). Pick a
  `--verify-time` before the expiry for every step below.
- **A pre-release outcome is not a failure.** At threshold T2 the §6.4 table can
  legitimately land a release in the trust pre-release channel (`v<core>-t<level>.<iteration>`).
  That is the honest channel; it is promotable later without changing source
  (§7.3). An *abort*, by contrast, means something is unverifiable — stop and fix
  it, never force past it.

## 1. Merge everything intended for the release

Land every PR meant for this release on `main` through the normal flow
(`scripts/merge-pr.sh`, signed and trailered merge commits). The release range
ends at the tip you are about to tag.

## 2. Fix the target commit

```sh
git fetch upstream
TO=$(git rev-parse upstream/main)
```

Everything below verifies and releases at `$TO`. Set `FROM` to the previous
release tag (`FROM=v0.1.0`); for the first release `FROM` is empty (`root..TO`).

## 3. MANUAL — incremental post-hoc review

Review the commits since the last release — the attestation asserts you stand
behind them — then emit a signed review attestation over the new range and push
the refs so outsiders can fetch them:

```sh
semver-trust attest review \
  --repo . --from "$FROM" --to "$TO" \
  --reviewer brad.pinter@gmail.com --verdict approved \
  --pr https://github.com/semver-trust/semver-trust-go/pulls \
  --key ~/.ssh/semver-trust-attest --store
git push upstream 'refs/attestations/*:refs/attestations/*'
```

This lifts agent-authored commits to T2 (agent + a distinct human review) and
clears meta-path commits past the §5.4 required level. Reviewing only the
incremental range keeps each release's ceremony small; prior ranges keep their
already-pushed attestations.

## 4. Pre-flight verify (either maintainer)

```sh
semver-trust verify --repo . --from "$FROM" --to "$TO" \
  --verify-time <RFC3339, before 2026-08-01>
```

Must complete §10 steps 1–7 with own/effective ≥ threshold (T2). If it aborts,
stop: the abort reason is the truth and the release must not be forced.

## 5. MANUAL — the release

```sh
semver-trust release \
  --repo . --from "$FROM" --to "$TO" \
  --claimed-bump <patch|minor|major> \
  --blast <low|moderate|high — your judgment, recorded as operator-supplied> \
  --tag-key ~/.ssh/semver-trust-attest --attest-key ~/.ssh/semver-trust-attest \
  --verify-time <RFC3339, before 2026-08-01>
```

`release` re-runs steps 1–7, decides the channel and version (step 8), then
emits the signed annotated tag and the release attestation (step 9). Use
`--dry-run` first to see the would-be tag and attestation without writing
anything. For a re-cut at the same core and level, bump `--iteration`.

## 6. MANUAL — push the tag and refs (publishing is automatic)

```sh
git push upstream 'refs/tags/<the tag>'
git push upstream 'refs/attestations/*:refs/attestations/*'
```

The tag push triggers `.github/workflows/release.yml`, which **re-verifies at
the recorded instant as an enforced gate**, then builds and publishes the
platform binaries, `checksums.txt`, the keyless cosign signature, and the SBOMs
to the GitHub Release, and refreshes the shields endpoint on the `badges` branch
so the README badge reflects the new release. If the workflow's verify job fails
for want of an attestation ref, it means step 3's push did not land — push the
refs and re-run.

## 7. Reproduce like an outsider (the flagship spot-check)

```sh
git clone https://github.com/semver-trust/semver-trust-go /tmp/fresh && cd /tmp/fresh
git fetch origin 'refs/attestations/*:refs/attestations/*'
go run ./cmd/semver-trust verify --repo . --from "$FROM" --to <the tag> \
  --verify-time <the attestation's recorded timestamp>
```

Same inputs, same instant, same decision — from public material alone. This is
the claim the whole project exists to make good on; run it every release.

## Promotion

Promotion moves a release from the pre-release channel to the clean channel
**without changing its source** (§7.3): attest the new evidence (a fresh
`attest review` over the release range, pushed as in step 3), then let
`promote` re-decide the same SHA:

```sh
semver-trust promote --repo . --tag <the pre-release tag> \
  --tag-key ~/.ssh/semver-trust-attest --attest-key ~/.ssh/semver-trust-attest \
  --verify-time <RFC3339, before 2026-08-01>
git push upstream 'refs/tags/<the clean tag>' 'refs/attestations/*:refs/attestations/*'
```

If the evidence has not changed the decision, `promote` refuses — promotion is
never a re-cut. The clean tag lands on the identical commit, and the new
attestation records the superseded envelope (§8.1); see
[reference/attestation-refs.md](reference/attestation-refs.md).
