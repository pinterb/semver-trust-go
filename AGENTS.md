# AGENTS.md — semver-trust/semver-trust-go

Contract for ALL coding agents working in this repository (Claude Code,
Codex, Cursor, aider, or anything else). `CLAUDE.md` is a pointer here;
this file is canonical.

The specification
repository (`github.com/semver-trust/spec`) is normative; its design
record (`docs/design-record.md`) §9 handoff contract is incorporated by
reference. This file adds the rules specific to writing code here.

## Sequencing gates (hard rules)

1. **No verification/release semantics before conformance vectors exist**
   in the spec repo (`conformance/`). The suite is this implementation's
   acceptance test; writing semantics first inverts the contract.
   Scaffolding, plugin interfaces, CLI skeletons, and fixtures are fine.
2. **Never emit an attestation** — even in tests marked temporary — with a
   placeholder predicate-type URI. The real URIs are bound and frozen at
   v0.1 (spec ADR-013; maintainer freeze decision 2026-07-06):
   `https://semver-trust.dev/release/v0.1` and
   `https://semver-trust.dev/review/v0.1`. Their additive-only evolution
   policy lives in the spec repository at
   <https://github.com/semver-trust/spec/blob/main/schemas/README.md>.
   Test fixtures use the real URIs with fake local subjects and test-only
   keys, per the spec repository's crypto fixture plan — a compliant
   fixture is a clearly-labeled test double that cannot escape the test
   tree.
3. **Pin the spec version** this code targets (currently draft v0.2) in
   one place; conformance is always claimed against a stated version.

## Provenance discipline (this repo dogfoods the scheme)

- Every commit is signed. Every commit carries `Provenance:` trailers
  (see `.gitmessage`); agent-authored commits use `Provenance: agent`
  with `Provenance-Agent: <tool>/<version>` naming whatever agent tooling
  is actually in use — the trailer scheme is tool-agnostic (spec §4.1).
  Do not commit without them.
- Merge commits only — never squash or rebase-merge (spec §4.3.3).
- History is never rewritten on `main`.
- An unbroken scheme-compliant history from commit #1 is a project
  deliverable in itself; breaking it recreates the adoption-boundary
  problem this repo exists to demonstrate the absence of.

## Layout and conventions

- `cmd/semver-trust/` — CLI entrypoint (`verify`, `release`, `attest`,
  `policy`, the plain-mode `list`/`latest`/`next`/`tag`).
- `internal/` — everything not part of the public plugin API:
  `version`/`plain` (parsers + plain mode), `vcs`, `sshsig`/`pgp` (signing
  key families), `trust`, `policy`, `attest`, `derive`, and `verify` (the
  §10 pipeline).
- Public packages only for the ADR-011 seams: `evidence/` (compatibility
  providers) and `graph/` (workspace graph adapters), plus registry
  projections.
- `conformance/` — the vendored, digest-pinned spec vectors and manifest
  (ADR-021); never hand-edited (refresh via `scripts/sync-conformance.py`).
- Tests run via `gotestsum` with agent-readable output formatting
  (maintainer convention); table-driven tests; fixture repositories are
  constructed by scripts, never committed as opaque `.git` blobs.
- Start with `verify` against synthetic fixtures before touching
  `release` (design record §8.8).

## Out of scope here

Spec text changes (spec repo), ADRs (spec repo `docs/adr/` — decisions
made while coding still get recorded there), and trademark/licensing
files (verbatim, do not modify).
