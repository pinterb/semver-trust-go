<!-- SPDX-License-Identifier: Apache-2.0 -->
# Documentation

New to the scheme? Start with **[concepts.md](concepts.md)** — what
SemVer-Trust is, why it exists, and what it does and does not promise, in
plain language.

## Find your guide

| Your situation | Read |
|---|---|
| You contribute code to a repository that uses SemVer-Trust | [guides/contributor.md](guides/contributor.md) |
| You are a coding agent authoring commits in such a repository | [guides/agent.md](guides/agent.md) |
| *Remaining guides land as they merge — new-repo bootstrap, legacy adoption, GitLab.* | |

## Reference

- [Provenance trailers](reference/trailers.md) — the trailer grammar, the
  `.gitmessage` template, and how humans and agents share one machine.
- [The policy file](reference/policy.md) — every field, and how to choose
  threshold, strategy, and meta-paths.
- [Trust material](reference/trust-material.md) — the `.semver-trust/`
  registries, the two-key model, and key enrollment.
- [Attestation refs](reference/attestation-refs.md) — where signed evidence
  lives in the repository and how it travels.
- [Reading verify output](reference/verify-output.md) — the report, step by
  step, and abort vs T0.
- [CLI reference](cli/semver-trust.md) — generated flag-level documentation
  for every command.

## This repository

- [architecture.md](architecture.md) — package map and invariants of the Go
  implementation.
- [release-runbook.md](release-runbook.md) — this repository's own release
  ceremony.
- [CONTRIBUTING](../CONTRIBUTING.md) — developing semver-trust-go itself.
- [Branch-protection rulesets](../.github/rulesets/README.md) — the
  two-ruleset model as committed artifacts.
- [history/](history/) — frozen records of how this repository was built
  (first-release ceremony, build-phase plan, legacy port audit).

## Normative sources

- The [SemVer-Trust specification](https://github.com/semver-trust/spec)
  (draft v0.3) — the normative text; these docs never override it.
- The [ADR index](https://github.com/semver-trust/spec/tree/main/docs/adr) —
  every design decision, with rationale and rejected alternatives.
- Conformance: this implementation vendors the spec's vector suite
  digest-pinned under [`conformance/`](../conformance/); the pinned spec
  version is in `conformance/manifest.json`.
