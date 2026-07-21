<!-- SPDX-License-Identifier: Apache-2.0 -->
# CLI Bootstrap Family — Implementation Plan

- **Date:** 2026-07-21
- **Status:** Implementation plan — executable task-by-task by a Sonnet/Opus-class model.
- **Implements:** [`docs/analysis/2026-07-19-cli-bootstrap-family.md`](../analysis/2026-07-19-cli-bootstrap-family.md)
  (the accepted proposal; its §3 documentation PR already shipped in #116).
- **Implementation target:** `semver-trust-go@a2fe62d` (`main`; the basis for the
  `file:line` references below).
- **Spec pin:** draft v0.10 (`conformance/manifest.json`, `58ec2d9`). The seven governing
  ADRs (M0) land in the `semver-trust/spec` repo as `docs/adr/0037`+.

This plan implements the code phases of the bootstrap-family proposal: the P0 verify seam
and the `doctor` / `enroll` / `setup` command family (the proposal's §4.1 initial
commitment). It is written to be executed in order, one milestone (and often one task) per
pull request, following strict red/green TDD — every task lands its failing test first,
then the minimal implementation, then the drift guard. It reuses existing production code
wherever the proposal's Appendix A named a primitive; the reuse map below is refreshed to
current `main`.

## Scope and decisions

- **In scope:** M0 (governing ADRs) + M1 (P0 seam) + M2 (`doctor`) + M3 (`enroll`) +
  M4 (`setup`).
- **Out of scope** (deferred by the proposal): `keys generate`, `init`, and the P3 remote
  horizon (`sync`, `doctor --online`, `reproduce`, `merge`). See the final section.
- **ADRs:** the proposal's seven §10 candidates are unfiled and gate the code. They are
  drafted as **M0** in the spec repo `docs/adr/` (ADR-0037+) and **ratified by the
  maintainer** before the code milestone each gates merges. They are tool-behavior ADRs —
  per the design-record mirror rule they do not cascade a `spec_version` bump provided none
  edits `spec/semver-trust.md`.

## Progress

Status of the milestones, updated as each lands.

| Milestone | Status | PR |
|---|---|---|
| M0 — governing ADRs | Not started | — |
| M1 — P0 seam extraction | Done | #125 |
| M2 — `doctor` | Not started (gated on M0) | — |
| M3 — `enroll` | Not started (gated on M0) | — |
| M4 — `setup` | Not started (gated on M0) | — |

M1 tasks: [x] 1.1 export `vcs.GitSSHNamespace` · [x] 1.2 `verify.LoadTrustMaterial` ·
[x] 1.3 `verify.ClassifyCommit` · [x] 1.4 this progress section.

## Corrections to the proposal (verified against `main`)

The proposal was pinned at an older commit (`71aec5a3`, pre-#76). These points are
reconciled to current `main`; carry them into the code:

- **No `vendor/` directory.** The proposal's "vendored x/crypto" is the module dependency
  `golang.org/x/crypto v0.54.0`; `ssh.MarshalAuthorizedKey` (`ssh/keys.go`) lives there and
  is currently unused, so the enrollment-line formatter is genuinely net-new.
- **The `"git"` namespace constant was unexported** (`gitSSHNamespace`). M1 exported it as
  `vcs.GitSSHNamespace` (`internal/vcs/verify.go:24`), since `enroll` / `doctor` live outside
  `internal/vcs` and need the commit-signing namespace.
- **The adoption boundary is descriptor-pinned (ADR-027/028), not policy-pinned.** ADR-026
  is superseded. Retarget the proposal's "ADR-026 extension" candidate to ADR-027/028, and
  phrase the `doctor` adoption-boundary check as "the in-policy value mirrors the descriptor
  and MUST match it" (spec §5.2).
- **The proposal's internal "ADR-4 / ADR-6 / ADR-7" mean items 4/6/7 of its own §10 batch**
  — not spec ADR-004/006/007. The drafted ADRs are numbered 0037+ and cross-referenced by
  title.
- **The spec is unchanged since the pin** (`58ec2d9` is still HEAD). ADR-036 is still
  *Proposed*, but only the deferred `chain/` and `reproduce` tiers depend on it — the
  initial three commands do not.
- `docs/reference/trust-material.md` still teaches the manual `echo >>` / `printf`
  enrollment the tool replaces; not a blocker, but `enroll`'s help/docs should cross-link it.

## Reuse map (current locations; wrap these, do not reinvent)

| Primitive | Location | Used by |
|---|---|---|
| `policy.Parse` (strict, digest) / `Marshal` round-trip | `internal/policy/parse.go:111` / `marshal.go:15` | doctor policy/, enroll re-parse |
| `sshsig.ParseAllowedSigners` / `Resolve` + `ErrUnknownSigner`, `ErrRevokedSigner` | `internal/sshsig/allowedsigners.go:44,203,193,196` | doctor registry/, enroll self-check |
| `pgp.ParseKeyring` / `Principals` | `internal/pgp/pgp.go:62,186` | doctor gpg-keyring, enroll gpg |
| `sshsig.LoadSigner` (passphrase-reject) / `Sign` | `internal/sshsig/sign.go:74,26` | doctor sign-roundtrip |
| `vcs.Tagger` (git identity) | `internal/vcs/create.go:70` | doctor identity, enroll principal default |
| `readTreeFile` / `MetaPolicyFromTree` | `internal/verify/tree.go:35` / `metapolicy.go:38` | doctor policy/registry tree reads |
| `attest.GitRefStore` `List`/`All`, `EnvelopeRef`, `validSubject` | `internal/attest/store.go:88,138,46,187` | doctor chain/refs; path-fence prior art |
| `attest.Namespace` (attestation) | `internal/attest/attest.go:39` | enroll/doctor namespace |
| `vcs.GitSSHNamespace = "git"` (exported in M1) | `internal/vcs/verify.go:24` | enroll/doctor namespace |
| resolvers `resolveHumanSigners` / `resolvePGPKeyring` / `buildAttestationVerifier` | `internal/verify/verify.go:773,803,834` | wrapped by the P0 `LoadTrustMaterial` seam |
| single-commit classify (loop body) | `internal/verify/verify.go:338-388` | carved into `ClassifyCommit` (P0) |
| `vcs.VerifyCommitSignature` | `internal/vcs/verify.go:100` | doctor simulate/commit |
| `trust.Classify` / `vcs.ParseTrailers` (final-paragraph rule) | `internal/trust/classify.go:93` / `vcs/trailers.go:70` | doctor simulate/classify |
| `ssh.MarshalAuthorizedKey` (unused) | `x/crypto@v0.54.0 ssh/keys.go:325` | enrollment-line formatter |
| `chain.AcceptedChainHead` | `internal/chain/predecessor.go` | doctor chain/chain-head (WARN/SKIP) |

## Test and house-style conventions (every task follows these)

- **Tests:** table-driven `[]struct{…}` + `t.Run` subtests; standard library only (no
  testify); `errors.Is` / `errors.As` on exported sentinels; small `assertX(t, …)` helpers
  with `t.Helper()`. No golden files — assert individual fields (JSON-unmarshal the result
  type) or `strings.Contains` on human output.
- **Signed fixture repos:** `conformance/vendor/crypto/build-fixture-repos.sh` builds
  `signed-history` / `unknown-signer` / `revoked-signer` / `gpg-signed` / `tampered` /
  `release` into a temp dir (pinned epoch `2026-01-01T00:00:00Z`). Wrap with the existing
  `buildFixtures(t)` helper (`internal/verify/fixtures_test.go:31`,
  `cmd/semver-trust/verify_test.go:94`). Ad-hoc signed history: `commitSignedCLI`
  (`cmd/semver-trust/release_test.go:583`); pure in-process signer: `ed25519.GenerateKey`
  with `ssh.NewSignerFromKey` (`internal/sshsig/sign_test.go:19`). Vendored test keys under
  `conformance/vendor/crypto/keys/`.
- **CLI tests:** `newRootCmd()` (`cmd/semver-trust/root.go:18`) → `SetOut`/`SetErr` buffers
  → `SetArgs([...])` → `Execute()`; assert on the returned `error` (nil = success) and
  buffer contents (`runRoot` helper, `cmd/semver-trust/policy_test.go:26`). Commands never
  `os.Exit`; `main` maps a non-nil error to `os.Exit(1)` (`main.go:20`). The clock is read
  once at the process boundary (ADR-018) and injected; `internal/*` stays clock-free.
- **Command house style:** `newXxxCmd()` constructor + `root.AddCommand` (`root.go:41-51`);
  parent+children like `newPolicyCmd` (`policy.go:27`); flag-vars declared at the top, bound
  at the end; `RunE` returns an error; output via `cmd.OutOrStdout()` and the `errWriter`
  helper (`cmd/semver-trust/write.go:14`); `SilenceUsage: true`.
- **Gates before every PR (exact):** `task test` · `task lint` · `task vuln` ·
  `task conformance` (must stay green — no evaluator or vector is touched anywhere in this
  plan) · `task docs:cli` (regenerates `docs/cli/`; commit it for each command-adding PR,
  since CI runs `docs:cli` then `git diff --exit-code`).

---

## M0 — Draft the seven governing ADRs (spec repo; maintainer ratifies)

One PR to the `semver-trust/spec` repo adding `docs/adr/0037…0043-*.md` plus the index row
in `docs/adr/README.md`. Drafted by the implementer; **ratified by the maintainer** (design
decisions are a human accountability act). Each code milestone names the ADR(s) that must be
`Accepted` before it merges. None edits `spec/semver-trust.md`, so no `spec_version` bump.

| ADR | Title | Gates |
|---|---|---|
| 0037 | Capability table — which command may write which path class; `verify`/`doctor` write-free permanently; `doctor --persona agent` the one agent-sanctioned command | M2, M3, M4 |
| 0038 | Generation/accountability line — the tool generates/formats/validates/configures; the human enrolls/commits/signs; print-by-default is the family invariant | M2, M3 |
| 0039 | The writer contract — atomic `O_EXCL`/temp-fsync-rename; dry-run zero-mutation; the repo-relative path fence for policy-named paths | M3, M4 |
| 0040 | Two-key distinctness is tool-enforced (fingerprint distinctness; attestation keys are SSH) — phrased not to widen ADR-022's normative scope | M2, M3 |
| 0041 | No adoption-boundary affordance on any generator (retarget of the "ADR-026 extension" to ADR-027/028 — the boundary is descriptor-pinned) | M2, M3 |
| 0042 | Environment tooling uses the git binary — the scoped exception to go-git-only: `setup` shells to `git config`; verification stays pure go-git (includes the verified go-git v5.19.1 corruption findings) | M4 |
| 0043 | Fetch refspec yes, push refspec never — ratifies the non-force fetch refspec already shipped in #116 | (docs shipped) |

**Verification:** the spec repo's own lint/build passes; the index lists 0037–0043 with
status; the immutable-supersession protocol (design-record §9.3) is respected; each ADR
cross-references the proposal §10 item it realizes.

## M1 — P0 seam extraction (refactor, no behavior change)

Gating ADR: none. Existing tests are the safety net; no vector or behavior changes. One PR:
`refactor: extract verify trust-material + single-commit seams (P0)`.

- **Task 1.1 — export the git namespace.** GREEN: rename `gitSSHNamespace` to exported
  `vcs.GitSSHNamespace` at `internal/vcs/verify.go:22` (update the in-package reference at
  `vcs/sign.go:80`). RED: a one-line test asserting the constant value `"git"`.
- **Task 1.2 — `verify.LoadTrustMaterial` seam.** RED: `internal/verify/seam_test.go`
  `TestLoadTrustMaterial` — for `signed-history`, assert the returned
  `(vcs.TrustedSigners, *attest.Verifier)` verify a known-good commit and reject
  `unknown-signer` (characterization: same outcome as today). GREEN: lift the inline block
  `verify.go:254-266` into the following, called by `verifyWith`; keep the three resolvers
  unexported so the seam is the only new exported surface:

  ```go
  func LoadTrustMaterial(opts Options, pol *policy.Policy, repo string) (
      vcs.TrustedSigners, *attest.Verifier, error)
  ```

- **Task 1.3 — `verify.ClassifyCommit` seam.** RED: `TestClassifyCommit` — per fixture
  (`signed-history` → pass row; `unknown-signer` / `tampered` → abort; `gpg-signed` →
  key-family), assert the `CommitReport` row and the `trust.Commit` classification. GREEN:
  carve `verify.go:338-388` into the following exported callable, called by `verifyWith`'s
  loop. It must be exported because `internal/preflight`'s `simulate/commit` check consumes
  it. It takes `repo` (needed for `VerifyCommitSignature`) and builds the attestation store
  internally; on failure it returns the same `*AbortError` (step 3) the loop produced:

  ```go
  func ClassifyCommit(repo string, c vcs.RangeCommit, trusted vcs.TrustedSigners,
      av *attest.Verifier, pol *policy.Policy, at time.Time) (
      CommitReport, trust.Commit, error)
  ```

- **Verification:** `task test` fully green (unchanged behavior), `task lint`, `task vuln`.
  No `docs:cli` (no CLI surface change).

## M2 — `doctor` (read-only diagnosis)

Gating ADRs: 0037, 0038, 0040, 0041. New package `internal/preflight` +
`cmd/semver-trust/doctor.go`. Split into 2–3 review-sized PRs (core + command, then checks,
then hardening).

- **Task 2.1 — enrollment-line formatter** (`internal/sshsig`). RED:
  `enroll_format_test.go` `TestFormatEnrollmentLine` — table over namespace
  `{"git", attest.Namespace}`; assert byte-exact
  `alex@example.com namespaces="git" ssh-ed25519 AAAA…` for a fixed key; refuse an empty
  principal/namespace. GREEN:
  `func FormatEnrollmentLine(principal, namespace string, pub ssh.PublicKey) (string, error)`
  via `ssh.MarshalAuthorizedKey`.
- **Task 2.2 — preflight core.** RED: `runner_test.go` — `TestSeverityExit` (any FAIL ⇒ the
  report signals non-zero; SKIP never does), `TestRenderContract` (no "all passed" verdict;
  a structural cannot-check footer; every FAIL carries `would abort at verify: §…` plus a
  `fix:` line). GREEN: `Check{ID, Personas, Run func(Env) Result}`,
  `Result{Severity, Msg, Preempts, Fix}` (Severity = PASS/WARN/FAIL/SKIP),
  `Runner.Run([]Check) Report`, `Report.Render(w io.Writer, strict bool)`,
  `Report.HasFail()`.
- **Task 2.3 — check families** (the §5 catalog). Pattern, applied once per check: RED = a
  fixture repo or message that must yield the exact severity and (for FAIL) a drift-guard
  assertion that the check wraps the same sentinel/classification `verify` uses; GREEN = the
  check calling the reused primitive. Families (persona M/C/A; full per-check list in
  proposal §5):
  - `config/` — identity, signing-enabled, commit-template, allowed-signers-file, hook (git
    config reads; all gated on worktree detection + the include caveat).
  - `keys/` — signing-key-loads, configured-vs-enrolled, attestation-distinct (ADR-022,
    checked by nothing today), attestation-family, sign-roundtrip (constant-only).
  - `registry/` — parse (tree+worktree drift WARN), self-enrolled (`Resolve`; on
    `ErrRevokedSigner` re-resolve under `attest.Namespace` to diagnose the namespace typo),
    principal-matches-email, gpg-keyring (empty ⇒ FAIL), bot-accounts.
  - `policy/` — parse (`policy.Parse`), meta-coverage, adoption-boundary (descriptor-match
    or loud SKIP; the boundary commit meets the active §5.4 meta gate — retargeted to
    ADR-027/028).
  - `simulate/` — classify (`--message`/`--commit` through `trust.Classify` — the
    non-final-paragraph trailer trap), commit (M1's `ClassifyCommit` — replaces
    `merge-pr.sh`'s grep), meta-touch (FAIL for agents), staged-purity, enrollment-line.
  - `chain/` — chain-head (read-only projection of `chain.AcceptedChainHead`; unique head +
    genesis→head verifies; no head ⇒ SKIP). WARN/SKIP tier.
  - `history/` — pre-adoption triage. `trust/` — agent-provenance (WARN).
  - `remote/platform/` — fetch-refspec (parsed-refspec compare; WARN + the exact
    `git config --add` fix), attestation-refs-local, rulesets (always SKIP →
    `check-rulesets.py`), release-baseline (INFO: latest tag, next `--from`, the
    recorded-instant reproduction line).
- **Task 2.4 — hardening.** `internal/pathfence` (reject-don't-sanitize like
  `attest.validSubject` + securejoin + `Lstat` symlink refuse — DR-1) applied to
  policy-named working-tree reads; the constant-only sign-roundtrip (DR-2); linked-worktree
  detection gating the config checks (SU-6); the `include`/`includeIf` disclosed caveat
  (SU-5).
- **Task 2.5 — `cmd/semver-trust/doctor.go`.** House-style command; persona auto-detect
  (principal in `attestation_signers` ⇒ maintainer, else contributor; `--persona agent`
  explicit ⇒ side-effect-free subset, `meta-touch` FAIL); flags
  `--repo/--persona/--staged/--commit/--message/--at/--strict/--json`; the clock read at the
  boundary; `RunE` returns an error when `Report.HasFail()` (⇒ exit 1); always ends by
  printing the filled-in `verify` invocation; `root.AddCommand(newDoctorCmd())`.
- **Verification:** `task test` (including the drift guards) + `lint` + `docs:cli` (commit
  `docs/cli/semver-trust_doctor.md`). Manual: the proposal §4.3 contributor and agent
  walkthroughs.

## M3 — `enroll` (registry generator + writer)

Gating ADRs: 0038, 0039, 0040. New `internal/enroll` + `cmd/semver-trust/enroll.go`.

- **Task 3.1 — print-by-default** (reuse 2.1). RED: `enroll --commit-key K` prints only the
  raw registry line to stdout, all guidance to stderr; the principal defaults from
  `vcs.Tagger`.
- **Task 3.2 — `--write`** under the writer contract. RED per rule: the path fence
  (traversal + symlink refuse — `internal/pathfence`), no parent-directory creation, strict
  re-parse of the whole result (`ParseAllowedSigners` / `ParseKeyring`), duplicate-key
  refusal, cross-registry (ADR-022) refusal, self-check via `Resolve` in the target
  namespace, mandatory fingerprint / `Principals()` disclosure, atomic temp+fsync+rename,
  `--dry-run` zero mutations.
- **Task 3.3 — GPG input** (`--gpg-pubkey FILE|-`): `pgp.ParseKeyring`, refuse private-key
  material loudly, require ≥1 new key, print the `Principals()` diff. No `gpg` shell-out;
  no bare key-id.
- **Task 3.4 — `cmd/semver-trust/enroll.go`** wiring + `root.AddCommand`.
- **Verification:** `task test` + `lint` + `docs:cli`. Manual: the §4.3
  greenfield-maintainer enroll steps.

## M4 — `setup` (this clone's git configuration only)

Gating ADRs: 0037, 0039, 0042. New `internal/setup` (or an `internal/vcs` config wrapper) +
`cmd/semver-trust/setup.go`. Shells to `git config` (ADR-0042) — never go-git `SetConfig`
(the verified lockless/corruption finding). No hook install — the committed hook plus the
printed `core.hooksPath` line already do it.

- **Task 4.1 — config writer.** Manages `gpg.format`, `user.signingkey`, `commit.gpgsign`,
  `commit.template` (only if `.gitmessage` exists), `gpg.ssh.allowedSignersFile`, and an
  append to `remote.<name>.fetch` (non-force). RED per rule: all-or-nothing conflict
  (compute the full change-set; any differing key ⇒ refuse, write nothing); `--force` prints
  `key: old→new` but never overwrites `user.signingkey`; idempotent re-run (`ok (already
  set)`; parsed-refspec comparison); reversal receipt (`git config --unset` per key);
  worktree/bare/`GIT_DIR`/`GIT_CONFIG*` detection (refuse-or-disclose); the include caveat;
  refuse `euid 0`; `--dry-run` emits the `git config` commands byte-for-byte (the dry-run is
  the manual fallback); the ADR-022 cross-check (the offered signing key is not in
  `attestation_signers`).
- **Task 4.2 — `cmd/semver-trust/setup.go`** wiring + `root.AddCommand`. The first output
  line of every run (dry-run included) echoes the resolved repo root, gitdir, and chosen
  remote/URL.
- **Verification:** `task test` + `lint` + `docs:cli`. Manual: the §4.3 maintainer and
  contributor setup.

## Out of scope (deferred by the proposal — do not build)

- **`keys generate`** — `sshsig.LoadSigner` rejects encrypted keys by design
  (`sign.go:77-81`); the un-defer trigger is passphrase / agent-held key support.
- **`init`** — decomposes into the §4.3 flow; the founding commit stays a
  read-it-yourself human act.
- **The P3 remote horizon** — `sync`, `doctor --online`, `reproduce` (additionally
  conformance-gated — no injected-clock/`reproduce` vector exists yet; only the clock input
  contract lives in `policy-transition`), and `merge`.

## Overall verification

- **TDD discipline:** every task lands its failing test first, then the minimal
  implementation; each `doctor` FAIL check additionally carries the drift-guard test
  (proposal principle 2) asserting it wraps the same sentinel/classification `verify` uses.
- **No regression:** M1 leaves `task test` and `task conformance` byte-identical (refactor
  only); no milestone touches an evaluator or a conformance vector.
- **Per-PR gates:** `task test lint vuln conformance` green; `task docs:cli` regenerated and
  committed for M2/M3/M4.
- **Acceptance:** run the proposal §4.3 persona walkthroughs (greenfield maintainer,
  contributor, legacy adopter, agent) end-to-end as manual sign-off.

## Delivery cadence

- **M0** — one PR to the spec repo (ADRs 0037–0043 + the index); the maintainer ratifies.
- **M1–M4** — PRs to `semver-trust-go` from `upstream/main`; signed commits with
  hand-authored provenance trailers; each command PR commits `docs/cli/`; the maintainer
  ratifies the gating ADR(s) and merges; ff-only sync and prune between milestones. A
  milestone may split into 2–3 review-sized PRs to keep diffs reviewable.
