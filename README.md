<!-- SPDX-License-Identifier: Apache-2.0 -->
# semver-trust-go

The official Go reference implementation of the
[SemVer-Trust specification](https://github.com/semver-trust/spec).

**Status: pre-implementation.** The specification is at draft v0.1; the
conformance suite that this implementation must pass does not exist yet.
No importable API or usable CLI is provided at this time.

## What this will be

A git-native tool that verifies commit-level provenance (signatures,
trailers, review attestations), aggregates it into release trust levels
(T0–T3) with path-scoped, transitively propagated flooring, and cuts
trust-encoded, attested releases — `verify`, `release`, and `policy`
commands, with plugin seams for evidence providers, workspace graph
adapters, and registry projections.

## Provenance

This repository practices the scheme it implements: every commit in its
history is signed and carries `Provenance:` trailers, from the first
commit onward. It will release itself with trust-tagged releases.

## License and trademark

Code is licensed under [Apache 2.0](LICENSE). Use of the SemVer-Trust
name and conformance claims are governed by the
[trademark policy](https://github.com/semver-trust/spec/blob/main/TRADEMARK.md);
this repository is the official implementation maintained by the
SemVer-Trust project.
