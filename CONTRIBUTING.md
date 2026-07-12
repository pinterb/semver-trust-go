# Contributing

semver-trust-go is the official Go reference implementation of SemVer-Trust,
tracking specification **draft v0.3**. Feedback and design discussion are
welcome as issues.

Pull requests: contribution terms (CLA or DCO) are being finalized and will be
documented here before external PRs are merged.

## One-time development setup

This repository's history must verify under the scheme it implements, so two
mechanical requirements apply to every commit — signed, and carrying
`Provenance:` trailers. Set both up once per clone:

```sh
# 1. Commit signing (SSH signing shown; gitsign or GPG also fine)
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git config commit.gpgsign true

# 2. Provenance trailer template
git config commit.template .gitmessage
```

Notes:

- The template pre-seeds `git commit` (editor flow). `git commit -m` bypasses
  templates — if you use `-m`, add the trailer yourself, e.g.
  `git commit -m "msg" --trailer "Provenance: human"`.
- Trailer semantics are defined by spec §4.1 and are tool-agnostic:
  human-authored commits use `Provenance: human`; agent-authored commits use
  `Provenance: agent` plus `Provenance-Agent: <tool>/<version>` for whatever
  agent produced the change (Claude Code, Codex, Cursor, aider, …); mixed
  authorship uses `Provenance: mixed`.
- Coding agents must follow `AGENTS.md` (the canonical agent contract;
  `CLAUDE.md` is a pointer to it for tools that only read that file).
- Unsigned or untrailered commits cannot be merged regardless of content.

## Development environment

Tooling is pinned outside the Go toolchain (which `go.mod` pins) via
[devbox](https://www.jetify.com/devbox) and [direnv](https://direnv.net/):
gotestsum, golangci-lint, markdownlint, yamlfmt, ruff, shellcheck, actionlint,
gitleaks, gitlint, and the release tooling. Install devbox and direnv, then in
the repository root:

```sh
direnv allow      # activates the pinned tools on cd (via .envrc / devbox)
```

Everything is driven through [Task](https://taskfile.dev). The table below is
generated from the Taskfile's `desc` fields and **kept in sync by hand** —
update it when you add or rename a task.

| Task | What it does |
|---|---|
| `task` (default) | Run linters, tests, and vulnerability checks |
| `task build` | Compile all packages |
| `task lint` | Run all linters (the `lint:*` chain below) |
| `task lint:go` | Run golangci-lint |
| `task lint:markdown` | Lint Markdown files |
| `task lint:yaml` | Lint YAML files (tracked files only) |
| `task lint:python` | Lint and format-check Python scripts (ruff) |
| `task lint:bash` | Run shellcheck on shell scripts |
| `task lint:gha` | Lint GitHub Actions workflows (actionlint) |
| `task fmt` | Format code and config (`fmt:go`, `fmt:yaml`) |
| `task test` | Run unit tests via gotestsum |
| `task conformance` | Run the conformance suite against the vendored, digest-pinned vectors (ADR-021) |
| `task vuln` | Check for known vulnerabilities (govulncheck) |
| `task docs:cli` | Regenerate the Markdown CLI reference under `docs/cli` from the command tree |
| `task mod` | Download and tidy Go modules (root and tools) |
| `task secrets` | Scan committed history for secrets (gitleaks) |
| `task commit-lint` | Lint the latest commit message (gitlint) |
| `task clean` | Remove build artifacts (`bin/`, `dist/`) |

The CLI reference under `docs/cli/` is generated, not authored: run
`task docs:cli` after changing any command's flags or help text and commit the
result. Regeneration is manual — there is no CI drift gate on it — so keeping it
current is part of a command-changing PR.

## Quality gates

Run the full suite before opening a PR; CI runs the same checks.

- **`task test`** — the unit and integration suite (gotestsum).
- **`task lint`** — golangci-lint plus the Markdown, YAML, Python, shell, and
  GitHub-Actions linters. `lint:go` must print `0 issues.`
- **`task conformance`** — the acceptance suite. "Conformance" here means the
  specification's own conformance vectors, consumed as **vendored,
  digest-pinned copies** (spec
  [ADR-021](https://github.com/semver-trust/spec/blob/main/docs/adr/0021-implementations-consume-conformance-artifacts-as-vendored-digest-pinned-copies.md)):
  the vectors live under `conformance/vendor/`, each pinned by digest in
  `conformance/manifest.json`, and a test fails if any vendored byte drifts from
  its pin. **Never hand-edit** `conformance/vendor/` or the manifest — the only
  refresh path is `python3 scripts/sync-conformance.py <spec-main-sha>`, which
  re-copies and re-pins from a stated spec commit.
- **`task vuln`** — govulncheck; a *called* vulnerability fails the build.

Two invariants are enforced in CI beyond the task suite:

- **The injected-clock guard (spec
  [ADR-018](https://github.com/semver-trust/spec/blob/main/docs/adr/0018-verification-interfaces-accept-injectable-trust-roots-and-clock-from-day-one.md)).**
  No package under `internal/{vcs,trust,attest,derive,sshsig}` may call
  `time.Now()`; the wall clock is read once at the `cmd/` boundary and injected.
  A `time.Now(` under the guarded packages fails CI. This is what makes
  verification reproducible against a recorded instant.
- **Commit hygiene.** Every commit must be signed and carry the `Provenance:`
  trailer block (§4.1); the subject follows Conventional Commits. Unsigned or
  untrailered commits are rejected.

## Pull request lifecycle

Branch from `upstream/main` (after `git fetch upstream`); every commit is signed
and ends with the trailer block (`Provenance:` / `Provenance-Agent:` / optional
`Provenance-Model:`). Open the PR against `semver-trust/semver-trust-go`.

Pull requests are **merged locally by the maintainer** (spec
[ADR-023](https://github.com/semver-trust/spec/blob/main/docs/adr/0023-merge-commits-are-created-locally-signed-and-trailered-never-by-web-flow.md)),
never through the web UI: a web-flow merge commit is unsigned-by-a-person and
untrailered, which classifies as ambiguous under §3.2 and would floor the
history. `scripts/merge-pr.sh <pr-number>` performs the flow — it verifies the
PR is open with green checks, creates a `--no-ff` merge commit signed by the
merger's key with `Provenance: human`, self-checks the signature and trailers,
and pushes. Merge commits only; squash and rebase merging are disabled by
policy. The branch ruleset keeps PRs and green checks required for everyone; a
single bypass-actor entry admits only the maintainer's signed merge commit. See
[`.github/rulesets/README.md`](.github/rulesets/README.md) for the ruleset model
and its drift check.

## Releases

Releases are cut with the tool's own `release` command following the repeatable
cadence in [`docs/release-runbook.md`](docs/release-runbook.md); the first
release is recorded in [`docs/history/first-release.md`](docs/history/first-release.md).
