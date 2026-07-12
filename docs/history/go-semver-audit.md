<!-- SPDX-License-Identifier: Apache-2.0 -->
# go-semver Audit (GO-005) — Input to Decision D2

> **Frozen record**: the legacy go-semver port audit that fed decision D2
> and ADR-020. Project-internal; kept for provenance of the ported code.

**Status:** complete · **Date:** 2026-07-06 · **Author:** agent (GO-005) ·
**Reviewer:** maintainer (pinterb)
**Purpose:** make decision **D2** decidable — *"incorporate `go-semver` as reviewed
re-commits carrying `Imported-From: go-semver@<sha>` trailers into this Apache-2.0
repo"* (implementation-plan §3 D2, blocks GO-020/GO-021).

Legacy repo audited (read-only): `/Users/bradpin/ext-code/go-semver`,
module `github.com/pinterb/go-semver`, HEAD `3dab798`.
It is small: 526 lines of Go across five packages, plus tests and CI/release config.

**Headline for the impatient reader.** No license blocker. All 24 commits are authored
by one natural person (Brad Pinter); there are zero third-party contributors, and the
maintainer has confirmed none of the code was written under CDW guidance, supervision, or
employment — so copyright vests wholly in him and he can license the port under Apache-2.0
directly. The code was MIT-licensed from the first commit (2019) until `3dab798`
(2026-07-02) flipped it to a CDW-excluding Custom license — but that flip touched **no
`.go` files**, so the port pulls the last MIT snapshot (`b427cc5`, = `3dab798^`), whose
code is byte-identical to HEAD, and the `Imported-From:` trailers point there rather than
at the Custom-licensed HEAD. See §3 and §6.

---

## 1. Inventory

### 1.1 Packages and exported identifiers

| Package | File | Exported identifier | Kind | Purpose |
|---|---|---|---|---|
| `main` | `main.go` | `main()` | func | Entrypoint; runs `cli.New().Execute()`. Contains a real bug (§5.7). |
| `internal/cli` | `commands.go` | `New() *cobra.Command` | func | Builds the root `semver` cobra command, flags, and `version` subcommand. |
| `internal/semver` | `semver.go` | `ReleaseType` | type (`int`) | Enum of increment levels. |
| | | `ErrInternalOnlyReleaseType` | var (error) | Sentinel: `pre` requested externally. |
| | | `ErrUnknownReleaseType` | var (error) | Sentinel: unrecognized increment level. |
| | | `(ReleaseType) String() string` | method | Name of a `ReleaseType` (`major`…`pre`). |
| | | `ToReleaseType(string) (ReleaseType, error)` | func | Parse a level string to a `ReleaseType`. |
| | | `Valid(string) (string, error)` | func | Parse+normalize a version, or error. |
| | | `Increment(string, ReleaseType, string) (string, error)` | func | node-semver-style version increment. |
| | | `Major(string) (uint64, error)` | func | Extract major component. |
| | | `Minor(string) (uint64, error)` | func | Extract minor component. |
| | | `Patch(string) (uint64, error)` | func | Extract patch component. |
| | | `Prerelease(string) ([]string, error)` | func | Split prerelease into dot-components. |
| | | `List([]string) ([]string, error)` | func | Filter valid versions, normalized, unsorted. |
| | | `SortedList([]string) ([]string, error)` | func | Filter valid versions, normalized, ascending. |
| `internal/git` | `tags.go` | `Tags(string) ([]string, error)` | func | Enumerate all tag refs (light + annotated) of a repo. |
| `internal/crlf` | `file_unix.go` / `file_windows.go` | `Linebreak` | const | `"\n"` (unix) / `"\r\n"` (windows), build-tagged. |

Unexported but load-bearing: `semver.list()` (the shared parse-and-filter loop),
`cli.validArgs` / `cli.handleVersions` (arg validation + the whole run path),
`git.rootPath` (directory resolution). The eight enum constants
(`major`…`pre`) are unexported; only `ReleaseType` and its two error sentinels are public.

### 1.2 CLI surface (from `commands.go` and `README.md`)

Single root command `semver` with a `Run` that validates/increments versions.

| Flag | Short | Type | Default (`NoOptDefVal`) | Behavior |
|---|---|---|---|---|
| `--increment` | `-i` | string | `patch` when bare | Increment level: major/minor/patch/premajor/preminor/prepatch/prerelease. |
| `--preid` | | string | (none) | Prerelease identifier prefix for the `pre*` levels. |
| `--repo-dir` | `-r` | string | cwd when bare | Use local git tags as the version source. |
| `--default` | `-d` | string | `0.0.0` when bare | Seed version when no valid version is supplied. |
| `--latest-only` | `-l` | bool | false | Emit only the highest version. |
| `--help` | `-h` | bool | — | Help. |

Subcommand: `version` (from `sigs.k8s.io/release-utils/version`) — prints build metadata.

Run semantics (`handleVersions`):

- Arg rules (`validArgs`): need at least one version **or** `--repo-dir`; more than one
  positional version **and** `--repo-dir` together is rejected.
- Sources are concatenated: optional `--default`, then positional args, then git tags.
- `SortedList` filters/normalizes/sorts. With no `--increment`: print the versions
  space-joined ascending (or just the max when `--latest-only`). With `--increment`:
  parse the level, increment the **highest** version, print the result.
- Errors print to stderr and exit code `2`.

### 1.3 Dependencies (`go.mod`, `go 1.18`)

| Direct module | Pinned | Latest (`go list -m -u`) | Maintained? | Role |
|---|---|---|---|---|
| `github.com/Masterminds/semver/v3` | v3.1.1 | v3.5.0 | Yes | Parse / precedence / component + prerelease access. |
| `github.com/spf13/cobra` | v1.5.0 | v1.10.2 | Yes | CLI framework. |
| `gopkg.in/src-d/go-git.v4` | v4.13.1 | (no update offered) | **No — abandoned** | Git tag enumeration. |
| `sigs.k8s.io/release-utils` | v0.7.3 | v0.12.4 | Yes | `version` subcommand + ASCII banner. |

Staleness notes. The `src-d` org was abandoned ~2019; go-git moved to
`github.com/go-git/go-git` (now v5) and `gopkg.in/src-d/go-git.v4` receives no updates —
this is a dead dependency and a mandatory replacement (§4). `Masterminds/semver` and
`cobra` are ~3 years behind but actively maintained; `release-utils` likewise. The
`go 1.18` directive (2022) is well behind this repo's toolchain (devbox Go 1.26). The
source also uses the deprecated `io/ioutil` (in `commands.go`'s dev-only `docs` helper).

---

## 2. Test coverage

| Package | Has tests | Coverage | Style | Notes |
|---|---|---|---|---|
| `internal/semver` | Yes | **83.9%** | Table-driven | The valuable suite; ~80-case `TestIncrement`. |
| `internal/git` | Yes | **62.1%** | Two fixed cases | **Clones live GitHub repos over the network** (§2.2). |
| `internal/cli` | No | 0% | — | The whole run path is untested. |
| `internal/crlf` | No | — | — | Trivial build-tagged constant. |
| `main` | No | — | — | Untested; `go vet` fails here (§5.7). |

Measured under the new repo's toolchain, `go1.26.4 darwin/arm64`.

### 2.1 What the tests cover

`internal/semver` (`semver_test.go`) is genuine table-driven Go: each test is a slice of
anonymous structs iterated in a loop. `TestReleaseTypes`, `TestValid`, `TestIncrement`,
`TestMajor`, `TestMinor`, `TestPatch`, `TestPrerelease`, `TestList`, `TestSortedList`.
`TestIncrement` is the crown jewel — it pins the node-semver-mimic behavior across the
full increment matrix (with and without a `preid`), and is the best raw material for the
GO-021 parity vectors. Most cases assert with `t.Fatalf` (stops at first failure);
`TestIncrement` uses `t.Errorf` (reports all). A local `Equal` helper compares slices.

### 2.2 The hermeticity problem in `internal/git`

`tags_test.go` (`TestNoTags`, `TestTags`) calls `git.PlainClone` against
`https://github.com/pinterb/semver-test-1` and `.../semver-test-3` at runtime. They pass
today (network was available; 62.1%), but they violate this repo's conventions directly:
AGENTS.md — *"fixture repositories are constructed by scripts, never committed as opaque
`.git` blobs"* — and ADR-016 (script-built fixtures). The ported `internal/vcs` tests
must be rebuilt as local, script-constructed fixtures with no network (§4, §5.8).

### 2.3 Build / vet status

`go build ./...` succeeds under Go 1.26 (exit 0). `go test ./...` **fails**, but only
because `go test` runs `go vet` and vet flags `main.go:11` (§5.7); the library packages
themselves pass. So: the code compiles and the library tests are green; the failure is a
genuine bug in the entrypoint, not a toolchain incompatibility.

---

## 3. Contributors and license history

### 3.1 Authorship — sole natural-person author, copyright vests in the maintainer

All 24 commits are authored by one natural person, the maintainer (Brad Pinter). There are
**no third-party contributors**: committers are the maintainer plus GitHub `web-flow` (the
six PR-merge commits), and the only `Co-authored-by` trailers in the entire history name
the maintainer himself (2 occurrences); there is no `Signed-off-by` from anyone else.

The maintainer confirmed, in the D2 decision session of 2026-07-06, that **none of this
code was written within the scope of employment or under the direction of CDW Corporation
or any other employer with a copyright-assignment claim.** No work-for-hire interest
therefore arises (17 U.S.C. §101), and copyright in the entire work vests in the
maintainer.

Per D2's decision rule ("sole author ⇒ relicense is trivial; non-trivial third-party
contributions would be blockers"), the contributor test is satisfied cleanly: **no
external contributor consent is required, and no CDW copyright interest exists.**

### 3.2 License history — MIT until 2026, and the flip touched no code

`git log --follow` over the license files:

| Date | Commit | Author identity | Event |
|---|---|---|---|
| 2019-09-10 | `5544960` (initial) | `pinterb` (personal) | `LICENSE` = **MIT**, "Copyright (c) 2019 Brad Pinter". |
| 2026-07-02 | `3dab798` (HEAD) | `brad.pinter@gmail.com` | Deletes `LICENSE` (MIT); adds `CUSTOM_LICENSE.md`; adds README notice. |

`3dab798` changed exactly three files — `LICENSE`, `CUSTOM_LICENSE.md`, `README.md` — and
**no `.go` files**. Its parent `b427cc5` (2022-10-04) is therefore the last snapshot whose
code is byte-identical to HEAD *but still under MIT*. The 2026 Custom license
("Copyright (c) 2026 Bradley Pinter") is source-available and **prohibits CDW Corporation,
its subsidiaries, affiliates, and employees** from any use; it governs copies distributed
under that version going forward. It does **not** retroactively revoke the MIT grant
already made on every earlier published snapshot — permissive licenses, once granted on a
copy, are not clawed back by a later relicense.

**Consequence for the port.** Because copyright vests in the maintainer (§3.1), he can
place the ported code under Apache-2.0 directly. Independently, the historical MIT grant on
every pre-`3dab798` snapshot remains valid and is not revoked by the later relicense, so
the code is also available under MIT. Either way, this fixes the provenance target: the
`Imported-From:` trailers must point at **`b427cc5` (the last MIT snapshot), not HEAD
`3dab798`**, so provenance trails
into MIT-licensed code rather than the CDW-excluding Custom snapshot.

---

## 4. Proposed port map

Target layout is implementation-plan §5. GO-020 (trust-version type) and GO-021 (plain
tag ops) are the consumers. **Note on the version type's home:** the plan lists
`internal/trust/` (levels/floors/decisions) and `internal/vcs/` (walk/trailers/tags) but
does not place the version type. I recommend a **dedicated leaf package
`internal/version`** rather than `internal/trust/version`. Rationale: the trust-version
type is a foundational value consumed by both plain-mode tag ops (`internal/vcs`, GO-021)
and trust semantics (`internal/trust`, GO-022+); a leaf package keeps "plain mode works
with zero trust config" honest and avoids `internal/vcs` having to import `internal/trust`
for its base type. (`internal/trust/version` is the fallback if the maintainer prefers
co-location.)

| Legacy identifier / file | Target | Disposition | Reason |
|---|---|---|---|
| `semver.ReleaseType`, `String`, `ToReleaseType`, error sentinels | `internal/version` | port-as-is | Clean enum; re-express tests table-driven. |
| `semver.Increment` (node-semver mimic) | `internal/version` | port-as-is | Hard-won, well-tested logic (§5.5); re-validate vs `precedence.json`. |
| `semver.Valid`, `Major`, `Minor`, `Patch`, `Prerelease` | `internal/version` | port-with-changes | Parser-swap decision (§5.1); fix silent `nil`-error paths (§5.6). |
| `semver.List` / `SortedList` / `list` | `internal/version` (feeds `internal/vcs` latest/next) | port-with-changes | Silent-drop decision (§5.2). |
| `git.Tags`, `git.rootPath` | `internal/vcs` | port-with-changes | Replace `src-d/go-git.v4` → `go-git/go-git` v5; script fixtures (§5.8). |
| `cli.New`, `handleVersions`, `validArgs` | `cmd/semver-trust/` + plain-mode `list\|latest\|next\|tag` (GO-041) | port-with-changes | Re-home as plain-mode subcommands; framework is `[P]` (§6). |
| `crlf.Linebreak` (+ `file_unix`/`file_windows`) | — | **drop** | CRLF hack only formats cobra help text; use standard help/wrapping. |
| `main.go` | `cmd/semver-trust/main.go` | port-with-changes | Fix the `log.Fatal` bug (§5.7); wire the new root. |
| `sigs.k8s.io/release-utils` `version` subcmd | — | **replace** | Use the repo's own `--version` (GO-026 pins/surfaces spec version). |
| `Masterminds/semver/v3` dep | — | decide (§5.1) | Keep+upgrade v3.5.0 (lenient) vs `golang.org/x/mod/semver` (strict). |
| `spf13/cobra` dep | — | `[P]` maintainer taste | cobra vs stdlib `flag` for `cmd/semver-trust`. |
| `gopkg.in/src-d/go-git.v4` dep | — | **replace** | Abandoned org; use `go-git/go-git` v5. |
| `Makefile` | — | **drop** | Replaced by Taskfile + devbox (ADR-016). |
| `.goreleaser.yml`, `.ko.yaml`, `godownloader-go-semver.sh` | — | **drop** | Release/image/install tooling out of scope; godownloader is deprecated. |
| `.golangci.yml`, `.editorconfig` | — | drop / re-derive | New repo supplies its own (GO-003); do not carry the `enable-all` config. |
| `go.mod`, `go.sum` | — | **drop** | New module already initialized (GO-003). |
| `LICENSE` (MIT) / `CUSTOM_LICENSE.md` | — | do not modify legacy | New repo is Apache-2.0; ported-file notices per §6 (AGENTS.md: don't touch license files). |

---

## 5. Behavioral quirks — parity input for GO-021 / GO-020

GO-021's acceptance is "behavior parity with go-semver's test suite for the ported
surface." These are the behaviors to consciously **preserve** or **break** — each needs a
decision, and most need a conformance vector.

### 5.1 Version normalization (coercion) — the parse∘format hazard

`Masterminds` is lenient: it strips a `v` prefix and back-fills missing components.
`v1`→`1.0.0`, `1.2`→`1.2.0`, `2.1`→`2.1.0`, `1.2-5`→`1.2.0-5`. The README example is exactly
this: `semver 2.1 v1.0.1 v3 4.x 5.12` → `1.0.1 2.1.0 3.0.0 5.12.0`. **Impact on GO-020's
acceptance** ("property test: parse∘format is identity on all valid tags from the org
tag-ruleset regex"): under Masterminds, parse∘format is identity *only* on the already-
canonical `x.y.z` subset — on `v1`, `1.2`, etc. it is not (it normalizes). If the org tag
regex admits `v`-prefixed or short forms, this property fails unless the parser is strict.
This is the port-as-is-vs-replace-the-parser crux: `golang.org/x/mod/semver` is strict
(requires `vX.Y.Z`, preserves `v`, gives full SemVer 2.0.0 precedence). **Decide in §6.**

### 5.2 Silent drop of invalid input

`list()` does `continue` on any parse error, so invalid entries (`4.x`, `foo`, `1.2.3.4`,
`1.2.3-alpha.01`) are **silently discarded** — no count, no warning. Convenient for a
plain "clean this list" CLI, but it brushes the spec's P4 honesty posture ("missing/
invalid is not silently passed"). Recommend: keep lenient filtering for the plain-mode
`list`, but surface a rejected-count; never let silent-drop reach trust decisions.

### 5.3 Sort order and latest

`SortedList` sorts **ascending** via `semver.Collection` (full precedence, prerelease <
its release). `--latest-only` returns the max (last element). Preserve; it matches SemVer
precedence and is what GO-021's `latest`/`next` want.

### 5.4 Default version `0.0.0`

`--default`/`-d` (bare → `0.0.0`) seeds the list so increment works in a fresh repo with
no tags: README's `semver -r -i -d` → `0.0.1`. Preserve as plain-mode `next` bootstrap.

### 5.5 Prerelease increment semantics (node-semver mimic)

`Increment` closely follows `npm/node-semver` (the README cites it). Behaviors pinned by
`TestIncrement` that GO-020 must preserve or explicitly document as divergent:

- patch/minor/major on a prerelease "settle" instead of bumping when the lower components
  are zero: `1.2.0-0` patch → `1.2.0`; `1.2.0-1` minor → `1.2.0`; `1.0.0-1` major → `1.0.0`;
  `1.2.3-4` patch → `1.2.3`.
- `prerelease` on a release acts like prepatch + `-0`: `1.2.4` → `1.2.5-0`.
- prerelease increment walks the **last numeric** identifier: `1.2.3-alpha.10.beta` →
  `1.2.3-alpha.11.beta`; `1.2.3-alpha.0.beta` → `1.2.3-alpha.1.beta`.
- a changed `preid` resets the counter: `1.2.3-dev.bar` (`preid=dev`) → `1.2.3-dev.0`.

These are the highest-value vectors to lift from `semver_test.go` into GO-021 and
cross-check against `precedence.json` / node-semver.

### 5.6 Swallowed errors inside `Increment`

Two internal paths return `"", nil` (success with empty result) instead of an error — the
`prePatch` `SetPrerelease` failure path returns `nil`, and the final `switch` has no
default. These mask failures. Break: return real errors on the port.

### 5.7 `main.go` `log.Fatal` bug — break, don't preserve

`main.go:11` is `log.Fatal("error during command execution: %v", err)`. `log.Fatal` does
**not** interpret format verbs (that is `log.Fatalf`), so it prints the literal `%v` and
appends `err` via default formatting. This is the `go vet` failure that fails `go test`.
Fix on port (`Fatalf`, or wrap and print cleanly).

### 5.8 Network-dependent git tests

Covered in §2.2: `internal/git` tests clone live GitHub repos. Break — rebuild as
script-constructed local fixtures with no network (AGENTS.md / ADR-016) when porting to
`internal/vcs`.

### 5.9 Numeric-range and leading-zero edge cases

Masterminds accepts components up to `uint64` (`1.2.2147483648` is valid) — wider than
node-semver's `MAX_SAFE_INTEGER`. It rejects leading-zero numeric prerelease ids
(`1.2.3-alpha.01`) but accepts hyphenated ones (`1.2.3-alpha.-1`, alphanumeric per SemVer
2.0.0). Note these if strict SemVer 2.0.0 conformance is a GO-020 goal; the parser choice
in §5.1 determines the exact edge behavior.

---

## 6. Recommendation — D2 decision packet

**Proposed disposition: PROCEED.** Port `go-semver` into this repo as fresh
signed/`Provenance:`-trailered re-commits carrying `Imported-From: go-semver@<sha>`
origin trailers; do **not** merge history (the rejected alternatives — history-preserving
merge and clean-room rewrite — stand rejected). Scope is the four small library/CLI
surfaces mapped in §4.

**Provenance target (important):** trailers point at **`b427cc5`** (the last MIT snapshot,
= `3dab798^`), not HEAD `3dab798`. `3dab798` changed only license/README files, so
`b427cc5`'s `.go` code is byte-identical to HEAD but under MIT — porting from HEAD would
trail provenance into the CDW-excluding Custom license, which is exactly what to avoid.

**License blocker status: NONE.** The maintainer is the sole author and owns the
copyright (§3.1) — he confirmed on 2026-07-06 that no CDW (or other employer)
work-for-hire interest exists — so he may license the ported code under Apache-2.0
directly. The only remaining choice is the SPDX
header carried on ported files:

- **Option A — relicense to Apache-2.0 (recommended).** As copyright holder the maintainer
  places the ported code under Apache-2.0; ported `.go` files carry
  `// SPDX-License-Identifier: Apache-2.0`, uniform with the rest of the repo.
- **Option B — retain the historical MIT grant.** The code was MIT from 2019 until
  2026-07-02; that grant is not revoked by the later relicense, so the `b427cc5` snapshot
  is also available under MIT. Ported files would keep `// SPDX-License-Identifier: MIT`
  plus the "Copyright (c) 2019 Brad Pinter" notice. An Apache-2.0 repo routinely contains
  MIT-licensed files; choose this only to preserve the original MIT provenance on these
  files.

**Third-party-contributor blockers: NONE** (§3.1) — no external contributor consent is
needed, and no CDW copyright claim exists.

**Open questions for the maintainer:**

1. **SPDX header** (§6 Options A/B) — Apache-2.0 (recommended) vs retained MIT. Decide
   before GO-020 writes file headers.
2. **Parser** (§5.1) — keep `Masterminds/semver` (lenient, upgrade to v3.5.0) or switch to
   `golang.org/x/mod/semver` (strict). Strict is needed for a clean parse∘format identity
   and full precedence; it changes normalization/edge behavior. Gates GO-020 acceptance.
3. **Silent-drop** (§5.2) — preserve lenient filtering in plain mode, or surface rejects?
4. **CLI framework** `[P]` — cobra (as-is) vs stdlib `flag` for `cmd/semver-trust`.

### Decisions taken (maintainer, 2026-07-06)

- **D2: PROCEED** — port as reviewed re-commits with `Imported-From: go-semver@b427cc5`
  trailers; recorded as an ADR in the spec repository.
- **Question 1: Apache-2.0** SPDX headers on ported files (Option A).
- **Questions 2–3: hybrid parser** — strict spec-§7.1 parsing for the canonical
  trust-version type and all tag/trust paths; lenient Masterminds-style coercion survives
  only in plain-mode list/validate for legacy CLI parity, with a surfaced rejected-input
  count (never silent, never in trust paths).
- **Question 4: open** — decide at GO-041 kickoff.
