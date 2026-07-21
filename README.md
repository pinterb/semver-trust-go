<!-- SPDX-License-Identifier: Apache-2.0 -->
# semver-trust-go

The official Go reference implementation of the
[SemVer-Trust specification](https://github.com/semver-trust/spec).

[![SemVer-Trust](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fsemver-trust%2Fsemver-trust-go%2Fbadges%2Fbadge.json)](https://github.com/semver-trust/spec/blob/main/spec/semver-trust.md#3-trust-model)

<!-- The badge reads the endpoint document on the `badges` branch, refreshed by
the release workflow on each verified release. -->

semver-trust is a git-native tool that reads the provenance of every commit in
a release range — signatures, `Provenance:` trailers, and review attestations —
aggregates it into a trust level (`T0`–`T3`) with path-scoped, transitively
propagated flooring, and cuts trust-encoded, cryptographically attested
releases. Low-trust releases sort *below* clean ones in ordinary SemVer
precedence, so an ecosystem's default resolution defers them the way it already
defers pre-releases — subject to per-ecosystem caveats, not a universal
zero-tooling guarantee ([conformance coverage](docs/conformance-coverage.md)).

## Status

`v0.1.0` is released. This is the official Go reference implementation of
SemVer-Trust. It vendors the specification's **draft v0.10** conformance
vectors (digest-pinned — see [the spec repository](https://github.com/semver-trust/spec));
which protocol capabilities are enforced versus still being adopted is tracked
in [docs/conformance-coverage.md](docs/conformance-coverage.md).

The repository releases *itself* under the scheme it implements. Its published
line runs `v0.1.0`–`v0.2.1` on the default `release/v0.1` chain, then **continues
onto the opt-in v0.10 authenticated chain at `v0.3.0`** (a `release/v0.2` genesis
that continues the line, §7.5/ADR-029) — every release cut on the clean channel at
effective trust **T2**, each decision re-derivable from a fresh public clone and the
attestation's recorded instant. The v0.1 decisions reproduce from in-tree trust
material; the `v0.3.0` decision reproduces against an out-of-band bootstrap
descriptor (see the [v0.10 transition
record](docs/history/2026-07-20-v0.10-transition.md)). The [reproduction
quickstart](#quickstart) below is that flagship claim, runnable.

## Install

```sh
go install github.com/semver-trust/semver-trust-go/cmd/semver-trust@latest
```

Prebuilt binaries for Linux, macOS, and Windows (amd64/arm64) are attached to
each [GitHub Release](https://github.com/semver-trust/semver-trust-go/releases),
alongside a `checksums.txt`, a keyless [cosign](https://docs.sigstore.dev/)
signature bundle over the checksums, and per-archive SBOMs. Verify the
checksums before trusting a binary:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/semver-trust/semver-trust-go/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

`semver-trust --version` prints the tool version and the conformance pin (the
spec draft version and the exact spec commit its vendored vectors came from).

## Quickstart

**1. Plain mode — enumerate and bump tags on any repository (zero
configuration).** These commands never read a policy; they operate on raw git
tags with node-semver increment semantics.

```sh
semver-trust list                # every tag, parsed and precedence-sorted
semver-trust latest              # the precedence-maximum version
semver-trust next -i=minor       # the version that would follow it (-i takes =value)
```

**2. Reproduce this repository's `v0.1.0` release decision (the flagship
claim).** An outsider re-derives the release from public material alone: a
clone, the published attestation refs, the in-tree trust material, and the
attestation's *recorded* verification instant (not the wall clock — the
maintainer's temporary signing key expires 2026-08-01, so the injected clock
must predate it).

```sh
git clone https://github.com/semver-trust/semver-trust-go /tmp/fresh
cd /tmp/fresh
git fetch origin 'refs/attestations/*:refs/attestations/*'
go run ./cmd/semver-trust verify --repo . --from '' --to v0.1.0 \
  --gpg-keyring .semver-trust/gpg-keyring.asc \
  --attestation-signers .semver-trust/attestation_signers \
  --verify-time 2026-07-12T03:30:00Z
```

Expected: the verifier walks `root..v0.1.0` (§10 steps 1–7), verifies
every commit's signature and covering review attestation, and reports **own
T2 → effective T2** for the default scope — the same inputs, the same instant,
the same decision that put the clean `v0.1.0` tag on this commit. (The
attestation refs are published by the maintainer's release ceremony; if the
fetch returns nothing, the release has not yet pushed them upstream.)

That command reproduces the published v0.1 chain from **in-tree** trust material
— the v0.3 path. The opt-in **v0.10 path** closes the last gap: a v0.10 release is
reproduced against an **out-of-band bootstrap descriptor supplied from outside the
clone**, which *authenticates* the in-tree policy and registries by digest rather
than trusting them because they happen to sit in the tree. This repository now
dogfoods that path too — its `v0.3.0` release is an authenticated `release/v0.2`
chain head continuing `v0.2.1`:

```sh
# <descriptor> is the out-of-band bootstrap descriptor, supplied from outside /tmp/fresh
go run ./cmd/semver-trust verify --repo . --to v0.3.0 \
  --bootstrap-descriptor <descriptor> \
  --verify-time 2026-07-21T00:00:00Z --chain-head
# accepted chain head: v0.3.0 -> 7d23a679… (effective T2, §7.5/ADR-029)
```

See the [v0.10 transition record](docs/history/2026-07-20-v0.10-transition.md) for the
full ceremony; the chain is also exercised by its [conformance
coverage](docs/conformance-coverage.md) and end-to-end tests.

**3. Explain the policy in effect.**

```sh
semver-trust policy explain
```

This prints the §6.4 decision table as configured in
[`.semver-trust/policy.toml`](.semver-trust/policy.toml) (threshold T2, strategy
`demote`), the meta-paths, and the declared scopes.

## How it works

A commit's trust level comes from *who is accountable* for it: its verified
signer's identity class (human vs. machine) combined with its `Provenance:`
trailers gives an authorship class, and cryptographically verified review
attestations give a review class; the §3.2 matrix maps the pair to `T0`–`T3`.
A release's own trust is the **weakest link** over the commits touching each
path scope, propagated as a floor across the internal dependency graph. The
policy's decision table then maps effective trust and blast radius to a channel:
clean, or the trust-tagged pre-release channel that default resolution defers
(subject to per-ecosystem caveats). See
[docs/concepts.md](docs/concepts.md) for the full picture in plain language.

## Commands

| Command | What it does |
|---|---|
| `verify` | Walk a release range and report per-commit provenance and effective trust (§10 steps 1–7); fails closed on anything unverifiable. |
| `release` | Decide the channel and version, then create the signed tag and emit the release attestation (§10 steps 8–9). |
| `promote` | Re-decide a pre-release at its own SHA with new evidence; if it now qualifies, cut the clean tag on the identical commit with a superseding attestation (§7.3). |
| `attest review` | Emit a signed §4.3 review attestation over a range of commits. |
| `policy validate` / `policy explain` | Parse a policy and print its digest, or render the decision table in effect. |
| `list` / `latest` / `next` / `tag` | Zero-configuration plain-mode tag operations (node-semver parity). |

Full flag-level reference: [docs/cli/](docs/cli/semver-trust.md) (generated from
the command tree via `task docs:cli`).

## Documentation

**[The documentation index](docs/README.md)** maps everything — persona
guides, reference pages, and this repository's own docs. The most-taken paths:

- [Concepts](docs/concepts.md) — what SemVer-Trust is and why, in plain language.
- [CLI reference](docs/cli/semver-trust.md) — every command and flag.
- [Contributing](CONTRIBUTING.md) — dev environment, quality gates, and PR lifecycle.
- [Specification](https://github.com/semver-trust/spec) and its
  [ADR index](https://github.com/semver-trust/spec/blob/main/docs/adr/README.md).

## Provenance

This repository practices the scheme it implements. Every commit in its history
is signed and carries `Provenance:` trailers, from the first commit onward, and
its releases (`v0.1.0`–`v0.2.1` on the default chain, then `v0.3.0` on the opt-in
authenticated v0.10 chain) ship with trust-tagged, reproducible release
attestations — the practice is demonstrated, not merely intended.

## License and trademark

Code is licensed under [Apache 2.0](LICENSE). Use of the SemVer-Trust name and
conformance claims are governed by the
[trademark policy](https://github.com/semver-trust/spec/blob/main/TRADEMARK.md);
this repository is the official implementation maintained by the SemVer-Trust
project.
