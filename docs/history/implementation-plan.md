<!-- SPDX-License-Identifier: Apache-2.0 -->
# semver-trust-go — Implementation Plan

> **Frozen planning record** of the build phase (GO-NNN work items,
> decision packets D1–D4). Spec-version references (draft v0.2) are as of
> its writing and are not maintained. For current documentation start at
> [../README.md](../README.md).

**Status:** active plan · **Date:** 2026-07-06 · **Owner:** maintainer (pinterb)
**Audience:** any human or agent executing build-phase work. This document is
detailed enough to start from zero context; read §1 before touching anything.

---

## 1. How to use this document

1. **Authority chain.** The specification
   (`semver-trust/spec` → `spec/semver-trust.md`, draft v0.2) is normative.
   The design record (`spec` → `docs/design-record.md`) and ADR log
   (`spec` → `docs/adr/`) explain and constrain decisions. This plan
   *sequences* the work; where it appears to conflict with spec or ADRs, they
   win and the conflict is a defect in this plan — report it.
2. **Work items** carry IDs (`GO-NNN`), explicit dependencies, a delegability
   marker — **[A]** agent-executable, **[M]** maintainer-only, **[P]** pair
   (agent drafts, maintainer decides) — and acceptance criteria. Do not start
   an item whose dependencies are open. Each item should map 1:1 to a GitHub
   issue; reference the ID in branch names and PR titles.
3. **Everything merges via PR** with the `drift`-equivalent checks green.
   Direct pushes to `main` are blocked by ruleset and must stay blocked.
4. **Decisions found mid-implementation** are recorded as ADRs in the spec
   repository (`docs/adr/`, next number, filename derived from title), never
   improvised in code comments. If an item forces an undocumented decision,
   stop and escalate rather than choose silently.

## 2. Ground rules (binding, from AGENTS.md and the ADR log)

- **Sequencing gates:** no verification/release *semantics* before the
  conformance vectors exist (ADR-013); **never** emit an attestation with a
  placeholder predicate URI, even in throwaway tests (predicate URIs:
  `https://semver-trust.dev/release/v0.1`, `…/review/v0.1`).
- **Provenance discipline:** every commit signed and `Provenance:`-trailered;
  merge commits only; no history rewrites. An unbroken verifying history from
  commit #1 is itself a deliverable (the adoption boundary for this repo is
  the first commit, by construction).
- **ADR-018 (interface invariant):** every verification-shaped function takes
  injected trust material (allowed-signers, CA/log roots, identity maps) and
  an injected clock from its *first draft*. No package-level globals, no
  `time.Now()` in verification paths, no ambient network fetch of trust roots.
- **ADR-011 (seams):** public packages only for evidence providers, workspace
  graph adapters, and registry projections. Everything else is `internal/`.
- **ADR-015:** `tools/go.mod` (+ `go.sum`) pins derivation-adjacent tools via
  the Go 1.24 `tool` directive; devbox pins DX-only tools (golangci-lint,
  gitsign, gh). devbox.lock is never a derivation input.
- **ADR-016/maintainer conventions:** devbox + direnv + Taskfile; gotestsum
  with agent-readable output (`testname` format, bounded failures);
  table-driven tests; fixture repositories built by scripts, never committed
  as opaque `.git` blobs.
- **P2/P4 honesty:** never infer authorship beyond what signatures prove;
  never waive evidence where a provider is missing — missing capability means
  lower provable trust, not equal trust asserted.

## 3. Pending decisions — blockers owned by the maintainer

These are **[M]** decision packets. Agents may draft the ADR text but MUST NOT
resolve them by writing code that assumes an answer.

- **D1 (ADR-020 candidate): merge-commit provenance under PR flow.**
  Web-UI merges are authored/signed by GitHub `web-flow` with no trailers —
  ambiguous under spec §3.2, flooring to agent-authored, which would poison
  this repo's own trust level at dogfood time. Options: (a) local `--no-ff`
  signed+trailered merges pushed by the maintainer; (b) define
  workflow-attested web merges as a recognized identity class (spec change,
  likely v0.3). Blocks Phase 6; decide before first trust tag.
- **D2 (ADR-021 candidate): incorporate `go-semver` as reviewed re-commits.**
  Port code as fresh signed/trailered commits carrying
  `Imported-From: go-semver@<sha>` origin trailers; do NOT merge history
  (would import unverifiable commits). Rejected alternatives to record:
  history-preserving merge; clean-room rewrite. Pre-work: license/contributor
  audit of go-semver (sole-author ⇒ relicense Apache 2.0 is trivial).
  Blocks GO-020/GO-021.
- **D3: this repo's own `policy.toml`** (scopes, meta-paths incl.
  `.github/workflows/**`, threshold, strategy) — needed by Phase 6 only.
- **D4: sigstore dependency pinning** — which sigstore-go release line to
  pin, and the update policy (Dependabot cadence vs. manual review for a
  meta-dependency of the verifier).

## 4. Phase plan

### Phase 0 — Repo ceremony and skeleton *(no dependencies)*

- **GO-001 [M] Create repository + settings.** Apache 2.0 via picker, Go
  `.gitignore`; merge-commits-only; import `branch-main-protection.json`
  ruleset (approvals 0, `required_signatures`, PR-required, check context
  updated to this repo's CI job); org tag ruleset already applies.
  *Accept:* direct push to `main` rejected; PR with green checks merges.
- **GO-002 [M] First-commit ceremony.** Starter-v2 files (README, AGENTS.md,
  CLAUDE.md pointer, CONTRIBUTING.md, `.gitmessage`), signed,
  `Provenance: human`. *Accept:* `git log --format='%G? %(trailers:key=Provenance)'`
  shows a verified, trailered root commit.
- **GO-003 [A] Toolchain + environment.** `go mod init
  github.com/semver-trust/semver-trust-go`; `tools/go.mod` with gotestsum via
  `tool` directive; devbox.json (go, golangci-lint, gitsign, gh, go-task),
  `.envrc`, Taskfile (`build`, `test`, `lint`, `verify`).
  *Accept:* `devbox run -- task test` green on empty test set; devbox.lock
  committed.
- **GO-004 [A] CI + supply-chain hardening.** Workflows: build/test/lint on
  PR + main; commit-hygiene check (every PR commit signed and
  `Provenance:`-trailered — this is the enforcement half of `.gitmessage`);
  actions SHA-pinned; Dependabot for `gomod` + `github-actions`.
  *Accept:* a PR containing an untrailered commit fails the hygiene check
  (prove with a deliberate fixture PR, then close it unmerged).
- **GO-005 [A] go-semver audit (feeds D2).** Inventory: exported functions,
  CLI surface, dependencies, test coverage, contributor list, license file.
  Deliverable: `docs/go-semver-audit.md` with a proposed port map
  (function → target package) and any license blockers.
  *Accept:* audit reviewed by maintainer; D2 decidable from it.

### Phase 1 — Contracts and vectors *(repo: `semver-trust/spec`; blocks 2+)*

- **GO-010 [A] JSON Schemas.** `schemas/release-v0.1.json`,
  `schemas/review-v0.1.json` per spec §8.1/§4.3, each with
  `$id: https://semver-trust.dev/schemas/<name>.json`; flip the predicate
  pages' "forthcoming" links. *Accept:* spec §8.1 example validates against
  the release schema; drift check green; schema files served at their `$id`
  URLs after Pages deploy.
- **GO-011 [A] Conformance core: levels + precedence.**
  `conformance/levels.json` (the §3.2 matrix as data, incl. ambiguous rows),
  `conformance/precedence.json` (ordered tag lists incl. `rc`-vs-`t`, the
  `t10<t2` hazard, iteration ordering). *Accept:* vectors self-validated by a
  script in `spec/scripts/`; README in `conformance/` documents the harness
  contract (inputs, expected outputs, versioning).
- **GO-012 [A] Conformance core: aggregation + decisions.**
  Scope-partition fixtures (diff-path lists → scope floors), propagation
  fixtures (graphs incl. an SCC cycle, the auth/billing/common worked example
  from spec Appendix A), decision-table vectors (trust × blast × strategy →
  channel/version). *Accept:* every spec Appendix A step reproduced as a
  vector; drift check green.
- **GO-013 [A] Crypto fixture plan (design only, build in Phase 3).**
  Document per ADR-018: vendored long-lived test keys, pinned verification
  clock values, keyless-case strategy. *Accept:* maintainer sign-off; no keys
  generated yet.

### Phase 2 — Core library *(depends: GO-011, GO-012; GO-020 also on D2)*

- **GO-020 [A] Trust-version type (port + extend).** Port go-semver's
  parse/sort/next-version logic per the D2 port map as reviewed re-commits
  with `Imported-From:` trailers; extend for the trust suffix
  (`-t<level>.<iteration>`), component-path tag prefixes, and full SemVer
  precedence. *Accept:* passes every `precedence.json` vector; property test:
  parse∘format is identity on all valid tags from the org tag-ruleset regex.
- **GO-021 [A] Plain tag operations (port).** Tag enumeration, latest/next
  computation, tag creation — the degraded-gracefully base layer (works with
  no policy file, no attestations). *Accept:* behavior parity with go-semver's
  test suite for the ported surface, re-expressed as table-driven tests.
- **GO-022 [A] Level assignment.** Authorship×review classification per spec
  §3.2 incl. ambiguity flooring. *Accept:* passes every `levels.json` vector.
- **GO-023 [A] Policy loader.** `policy.toml` per spec §9: scopes, weights,
  meta-paths, derivations, identity maps, thresholds, strategy. *Accept:*
  spec §9 reference example round-trips; unknown keys are errors, not
  warnings (config is root of trust).
- **GO-024 [A] Scopes, floors, propagation.** Diff-path partitioning,
  per-scope floor, graph propagation with SCC collapse; graph-adapter seam
  (public) with a `gomod` adapter first. *Accept:* passes aggregation
  vectors incl. the Appendix A worked example end-to-end.
- **GO-025 [A] Decision engine.** Semantic floor (compat-differ seam, with
  `apidiff` provider) + evidence ceiling + `demote`/`inflate`. *Accept:*
  passes decision vectors; where no differ is configured, "differ required"
  cells resolve to pre-release (P4 honesty — assert this in tests).
- **GO-026 [A] Conformance harness.** Test target that consumes the spec
  repo's `conformance/` vectors (pinned spec version) and fails on any
  mismatch. *Accept:* `task conformance` green; spec version pinned in one
  place and surfaced by `--version`.

### Phase 3 — Git + cryptographic verification *(depends: Phase 2)*

- **GO-030 [A] Commit walk + trailer parse.** Range enumeration
  (`FROM..TO`, root..TO for first release), trailer extraction, merge-commit
  conflict-hunk detection (spec §4.3.4). *Accept:* fixture repos (script-built)
  cover squash-forbidden, merge-with-conflict, first-release cases.
- **GO-031 [A] Signature verification: SSH allowed-signers.** Injected
  registry + clock (ADR-018). *Accept:* vendored-test-key fixtures verify at
  a pinned clock; verification fails closed on unknown signer (unverifiable
  ⇒ abort, never T0 — spec §5.2; assert in tests).
- **GO-032 [P] Signature verification: sigstore keyless.** sigstore-go
  (pinned per D4), injected Fulcio/Rekor roots + clock. *Accept:* fixture
  strategy per GO-013 executes; no network in unit tests.
- **GO-033 [A] Attestation verify + storage adapters.** DSSE/in-toto
  Statement verification against the JSON Schemas; storage seam with
  `git-ref` (`refs/attestations/*`) adapter first. *Accept:* schema-invalid
  and signature-invalid attestations both abort with distinct errors.
- **GO-034 [A] Derivation-proof runner.** Execute pinned commands, byte-diff
  outputs, re-level per spec §4.4 incl. the formatting degenerate case.
  *Accept:* fixture with an oapi-codegen-style derivation inherits input
  trust; tampered output voids the proof and is reported.

### Phase 4 — CLI *(depends: Phase 3; spec §10 is the skeleton)*

- **GO-040 [A] `verify`.** Walk a range, per-commit provenance report,
  effective-trust computation; human table + `--json`. Build against
  fixtures before any other command. *Accept:* spec §10 steps 1–7 traceable
  in output; abort semantics match §10 exactly.
- **GO-041 [A] `policy` (validate/explain) and plain-mode `list|latest|next|tag`**
  (the go-semver surface, working with zero configuration). *Accept:*
  plain-mode works in a repo with no policy.toml; `policy explain` prints the
  decision table in effect. Out-of-grammar tags (build metadata, malformed
  trust shapes) are tolerated for display/list parity; trust operations
  refuse them (maintainer decision 2026-07-07: canonical parse rejects
  build metadata — alias-attack surface; rejection is scoped per surface).
- **GO-042 [A] `release`.** Evaluate → decide → signed annotated tag →
  release attestation (real predicate URIs only) → store. *Accept:* spec §10
  steps 8–9; emitted attestation validates against `release-v0.1.json`;
  refuses to run if policy file fails meta-path trust (fixture).

### Phase 5 — Demand side + keystone *(depends: Phase 2 core; ADR-017: equal priority with Phase 4)*

- **GO-050 [A] `verify` GitHub Action + badge.** Composite action running
  `verify`; badge endpoint/artifact ("SemVer-Trust: T2 ✓"). *Accept:* action
  runs on this repo's own PRs; badge renders in a test README.
- **GO-051 [P] Retrospective profiling.** Platform adapter (GitHub API) to
  reconstruct review facts; compute would-have-been trust profiles over
  existing history at an injected clock. *Accept:* profile of this repo and
  of one public OSS repo produced; caveats section auto-emitted (what could
  not be verified and why — P2 honesty). Foreign-repo histories legitimately
  contain out-of-grammar tags (npm-style `+metadata`); the retro path
  classifies them as out-of-grammar in the caveats and never crashes.
- **GO-052 [M] E2 study design.** How retro profiles get compared to
  CVE/incident data (spec §12.8). Design doc only; execution is post-1.0.

### Phase 6 — Dogfood *(depends: Phases 3–4, D1, D3)*

- **GO-060 [M] ADR-020 resolution implemented** (merge provenance).
- **GO-061 [P] Repo `policy.toml` + first trust-tagged release.**
  `semver-trust release` cuts this repo's own tag; attestation published;
  README badge switches to live. *Accept:* an independent `verify` run
  (fresh clone, injected roots) reproduces the release decision — the
  flagship claim, demonstrated.
- **GO-062 [A] go-semver supersession notice** in the old repo: archived
  status, pointer here, command-mapping migration table from the GO-005
  audit.

## 5. Target package layout

```
cmd/semver-trust/          CLI (cobra or stdlib flag — maintainer taste; [P])
internal/vcs/              commit walk, trailers, tags
internal/trust/            levels, floors, propagation, decisions
internal/attest/           DSSE/in-toto verify + emit
internal/policy/           policy.toml
internal/derive/           derivation-proof runner
evidence/                  PUBLIC seam: compat differs, coverage (apidiff first)
graph/                     PUBLIC seam: workspace graph adapters (gomod first)
registry/                  PUBLIC seam: registry projections (later phase)
conformance/               harness consuming spec-repo vectors
tools/go.mod               gotestsum et al. (ADR-015 boundary)
```

## 6. Definition of done

Per phase: all items' acceptance criteria met, `task verify && task test &&
task conformance` green, no ADR-018 violations (grep-able: no `time.Now()`
under verification packages — add this as a lint/CI check in GO-004's
follow-up). Overall exit: **GO-061** — this repository carries a trust-tagged
release whose decision an outsider can reproduce from public material alone.

## 7. Risks

sigstore API churn (mitigate: D4 pinning + thin wrapper); conformance-vector
drift vs. spec v0.3 (mitigate: pin + GO-026 single-source version); GitHub
API limits in GO-051 (mitigate: cache, injected transport); scope creep into
spec changes (mitigate: §1.4 escalation rule — this plan builds v0.2, spec
changes go through the spec repo's process).
