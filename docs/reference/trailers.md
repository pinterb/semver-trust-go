<!-- SPDX-License-Identifier: Apache-2.0 -->
# Provenance trailers

Every commit in a SemVer-Trust repository declares who authored it — a human, an
agent, or both — in git trailers at the end of the commit message. This page is
the reference for that block: the exact grammar, how to produce it from the
command line, and how one machine can host both human and agent commits without
the two contaminating each other. The normative text is
[spec §4.1](https://github.com/semver-trust/spec/blob/main/spec/semver-trust.md#41-provenance-trailers);
what a trailer does to a commit's trust classification is
[spec §3.2](https://github.com/semver-trust/spec/blob/main/spec/semver-trust.md#32-classification).

## The grammar

The trailer block is the final paragraph of the commit message. One key is
required, two are qualifiers:

```text
Provenance: agent | human | mixed
Provenance-Agent: <tool>/<version>        (required when Provenance != human)
Provenance-Model: <model-identifier>      (optional)
```

- **`Provenance: human`** — a person wrote this change.
- **`Provenance: agent`** — a coding agent wrote this change. Name the tool in
  `Provenance-Agent` (`claude-code/2.8`, `aider/0.86`, `cursor/0.51`, …);
  optionally name the model in `Provenance-Model`.
- **`Provenance: mixed`** — a person and an agent both materially authored the
  change (an agent draft substantially edited by a human, or the reverse).
  `Provenance-Agent` is required here too.

A complete agent block names the tool, its version, and — optionally — the
model actually in use. Substitute the real values; these are placeholders, not
literals to copy (a fictional model line is still mis-provenance):

```text
Provenance: agent
Provenance-Agent: claude-code/<version>
Provenance-Model: <model-id>
```

Two rules from the spec worth internalizing:

- **Trailers are self-asserted and advisory.** They refine classification but
  never override what the signature proves: a commit that *claims*
  `Provenance: human` while being signed by a machine identity classifies as
  **ambiguous** (spec §3.2), which is the weakest authorship class. You cannot
  launder agent work into human credit with a trailer.
- **`Co-authored-by:` is corroborating, never substituting.** Agent tooling
  that appends `Co-authored-by:` lines provides supporting evidence of agent
  involvement, but where the policy requires a `Provenance:` trailer
  (`[trailers] require = true`), only a `Provenance:` trailer satisfies it.

## What happens without one

When the policy sets `[trailers] require = true`, a commit with no `Provenance:`
trailer on a protected branch is a policy violation — repositories typically
reject it in CI (this repository's commit-hygiene check does) or at the
[commit-msg hook](#the-commit-msg-hook) below. If an untrailered commit does
enter history, classification falls back to what the signature alone supports,
and any mismatch between claim and evidence lands in **ambiguous** — which
floors at T0 without review (spec §3.2). Honesty is cheap; its absence is
priced in.

The fix, before the commit leaves your machine:

```sh
git commit --amend --no-edit --trailer "Provenance: human"
```

(Amending re-signs the commit. Never amend commits that are already on a
shared branch — fix forward instead.)

## Producing the trailer

Interactively, the repository's commit template pre-fills it (see below).
Non-interactively, pass it explicitly:

```sh
git commit -m "fix: reject empty policy keys" --trailer "Provenance: human"
```

The `-m` flag **bypasses the commit template** — this is the single most common
way to lose the trailer. Either add `--trailer` alongside `-m`, or install the
hook below so the omission cannot survive.

## One machine, two authors: humans and agents side by side

A maintainer's laptop routinely produces both kinds of commit: the human's own
work, and an agent's work from the same checkout. The two must carry different
trailers, and neither may inherit the other's. The separation rests on a fact
about git itself: **`commit.template` only pre-fills interactive editors.**
A template never touches `git commit -m`, `-F`, or anything an agent harness
generates. That gives each author class its own channel:

| Channel | Who uses it | Where the trailer comes from |
|---|---|---|
| Interactive editor | The human | `.gitmessage` template, pre-filled `Provenance: human` |
| Non-interactive (`-m`/`-F`) | The agent | The agent authors its full block explicitly, every commit |

Concretely:

**The template carries the human default.** Commit a `.gitmessage` at the
repository root and point config at it:

```sh
git config commit.template .gitmessage
```

This repository's template (the human line active, the agent block present as
commented guidance):

```text
# --- SemVer-Trust provenance trailers (required on every commit) ---
# Keep trailers as the final block. Pick ONE Provenance value.
# Human-authored:
Provenance: human
# Agent-authored — replace the line above with the following, using
# whatever agent tooling produced the change (spec §4.1):
# Provenance: agent
# Provenance-Agent: <tool>/<version>     e.g. claude-code/2.8, codex/1.4,
#                                        cursor/0.51, aider/0.86
# Provenance-Model: <model-id>           optional
# Mixed human+agent authorship:
# Provenance: mixed
```

**The agent never relies on the template.** An agent MUST write its complete
trailer block into every commit message it authors (see the
[agent contract](../guides/agent.md)). This repository instructs its agents to do
exactly that in `AGENTS.md`; the agent harness composes the message, so the
human default in the template is never in play for agent commits.

**The signing key may be shared.** Both kinds of commit can be signed by the
same key — typically the human's, since the agent runs under their account.
That is fine by design: the signature is the *accountability anchor* (who
stands behind the commit entering history), the trailer is the *authorship
claim* (who wrote it). An honestly-trailered agent commit signed with the
maintainer's key classifies as agent-authored, and one signed human review
lifts it to T2 — the reviewer may even be the same identity that signed it
(spec repository ADR-025: self-review exclusion prevents counting one human
twice, never counting them once). A dedicated agent signing key is optional
hardening, not a requirement.

**Separate checkouts can carry separate config.** If your agent works in
dedicated clones or worktrees, `includeIf` gives each directory its own
identity without touching the global config:

```ini
# ~/.gitconfig
[includeIf "gitdir:~/work/agent-checkouts/"]
    path = ~/.config/git/agent.gitconfig
```

where `agent.gitconfig` sets its own `user.name`, `user.email`, and
`user.signingkey`. This is optional; the template/explicit split above is
sufficient on its own.

## The commit-msg hook

A local hook makes the trailer impossible to forget, for humans and agents
alike — it inspects the final message, whichever channel produced it. This
repository ships the hook in-tree at [`.githooks/commit-msg`](../../.githooks/commit-msg),
so there is nothing to copy: enable it once per clone by pointing git at the
committed hooks directory.

```sh
git config core.hooksPath .githooks
```

The hook body is a few lines — it parses the message and refuses anything
without a well-formed `Provenance:` trailer:

```sh
if ! git interpret-trailers --parse "$1" | grep -Eq '^Provenance: (human|agent|mixed)$'; then
  echo "commit rejected: missing or malformed 'Provenance:' trailer" >&2
  echo "add one of:  Provenance: human | agent | mixed  (spec §4.1)" >&2
  exit 1
fi
```

Verified behavior:

```console
$ git commit -m "feat: something"
commit rejected: missing or malformed 'Provenance:' trailer
add one of:  Provenance: human | agent | mixed  (spec §4.1)

$ git commit -m "feat: something" -m "Provenance: human"
[main 1178f0b] feat: something
```

Hooks are advisory (anyone can skip them with `--no-verify`); the enforcing
copy of this rule belongs in CI and, ultimately, in verification itself —
`semver-trust verify` reads the trailers that actually entered history, and
classification prices in whatever it finds there.

## See also

- [Working in a repository that uses SemVer-Trust](../guides/contributor.md) —
  the human's day-to-day flow.
- [Agent contract](../guides/agent.md) — the rules an agent must follow.
- [Trust material](trust-material.md) — how signing keys get enrolled.
- [Reading verify output](verify-output.md) — where a bad trailer shows up.
