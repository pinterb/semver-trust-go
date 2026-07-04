# Contributing

semver-trust-go is pre-implementation, tracking SemVer-Trust spec draft
v0.1. Feedback and design discussion are welcome as issues.

Pull requests: contribution terms (CLA or DCO) are being finalized and
will be documented here before external PRs are merged.

## One-time development setup

This repository's history must verify under the scheme it implements, so
two mechanical requirements apply to every commit — signed, and carrying
`Provenance:` trailers. Set both up once per clone:

```sh
# 1. Commit signing (SSH signing shown; gitsign or GPG also fine)
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git config commit.gpgsign true

# 2. Provenance trailer template
git config commit.template .gitmessage

# 3. Toolbelt: install devbox and direnv, then direnv allow in the repo root — 
the pinned tools (gotestsum, golangci-lint, gitsign, gh) activate on cd. The Go
toolchain itself is pinned by go.mod and needs no manager. 
```

Notes:

- The template pre-seeds `git commit` (editor flow). `git commit -m`
  bypasses templates — if you use `-m`, add the trailer yourself, e.g.
  `git commit -m "msg" --trailer "Provenance: human"`.
- Trailer semantics are defined by spec §4.1 and are tool-agnostic:
  human-authored commits use `Provenance: human`; agent-authored commits
  use `Provenance: agent` plus `Provenance-Agent: <tool>/<version>` for
  whatever agent produced the change (Claude Code, Codex, Cursor, aider,
  …); mixed authorship uses `Provenance: mixed`.
- Coding agents must follow `AGENTS.md` (canonical agent contract;
  `CLAUDE.md` is a pointer to it for tools that only read that file).
- Merge commits only; squash and rebase merging are disabled by policy.

Unsigned or untrailered commits cannot be merged regardless of content.
