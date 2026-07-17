<!-- SPDX-License-Identifier: Apache-2.0 -->
# Agent contract for SemVer-Trust repositories

You are a coding agent authoring commits in a repository that follows
SemVer-Trust. This page is your contract: generic to every such repository,
written to be loaded into your context and obeyed. The repository you are in
may add stricter rules of its own — see [the last section](#repository-specific-overrides).

> **Repository authors:** the block in the next section is self-contained —
> copy it verbatim into your `AGENTS.md` (or the file your `CLAUDE.md` points
> at) to give agents these rules directly, with no dependency on this page. The
> sections after it explain the reasoning and the mechanics in full.

## Drop-in contract for your `AGENTS.md` / `CLAUDE.md`

Copy everything between the fences into your repository's agent contract. It is
complete on its own — it inlines the trailer format and references no other
file, so an agent that reads only your `AGENTS.md` has everything it needs:

````markdown
## For AI coding agents: commit provenance rules

This repository verifies commit provenance and human accountability
cryptographically (SemVer-Trust). Your commit messages are part of that
evidence — lying in them costs the repository more than honesty ever could.
When you author a commit here:

1. **Keep commit signing enabled.** Your commits are normally signed by the
   operator's key; that is correct and records who is accountable for the
   commit entering history. Never disable signing.

2. **End every commit message with a truthful Provenance trailer** as its final
   paragraph, authored explicitly on every commit (do not rely on a
   `.gitmessage` template — `git commit -m`/`-F` bypasses it):

   ```text
   Provenance: agent
   Provenance-Agent: <your-tool>/<version>
   Provenance-Model: <model-identifier>
   ```

   - Use `Provenance: agent` when you are the sole author; use
     `Provenance: mixed` (with the same `Provenance-Agent` line) when a human
     substantially co-authored the change.
   - **Never** write `Provenance: human`. A `Co-authored-by:` line is
     corroborating evidence only — it never replaces the `Provenance:` trailer.
   - `Provenance-Model` is optional but honest; include it when you know it.

   Attach the block inline or with `--trailer`:

   ```sh
   git commit -m "feat: <subject>" \
     -m "Provenance: agent
   Provenance-Agent: <your-tool>/<version>
   Provenance-Model: <model-identifier>"
   ```

   If a commit you just authored has a wrong or missing trailer, fix it with
   `git commit --amend` **before pushing** (amending re-signs). Never amend a
   commit already on a shared branch — report the problem to your operator
   instead.

3. **Never emit review or release attestations** (`semver-trust attest …`,
   `semver-trust release …`, `semver-trust promote …`). Signing an attestation
   is a human accountability act and cannot be delegated to you.

4. **Never merge through the platform's web UI**, and never rewrite history on
   shared or protected branches. Merges are created locally and signed by a
   maintainer.

5. **Before editing trust material** — the policy file under `.semver-trust/`,
   any key registry, a CI workflow file, or a branch-protection artifact — stop
   and surface the change to your human operator instead of pushing it. These
   files are the root of trust.

6. **If verification aborts on your commit**, that is fail-closed behavior
   working, not a low score. Do not retry, work around the verification, or
   touch the trust material: read the one-line reason, report it to your
   operator with the failing step, and stop.
````

## The contract

- You MUST ensure every commit you author is signed (the harness or operator
  configuration normally handles this; do not disable it).
- You MUST end every commit message you author with a complete, truthful
  Provenance trailer block (next section).
- You MUST NOT claim `Provenance: human`, ever. If a human substantially
  co-authored the change, the honest value is `mixed`.
- You MUST NOT rely on the repository's `.gitmessage` commit template for
  your trailers — it carries the *human* default, and `git commit -m`/`-F`
  (how you commit) bypasses it anyway. Author your block explicitly, every
  commit.
- You MUST NOT rewrite history on shared or protected branches, and MUST NOT
  merge through the platform's web UI — merges here are created locally and
  signed by a maintainer (spec repository ADR-023).
- You MUST NOT emit review or release attestations. Signing an attestation is
  a human accountability act (specification Principle 2); it cannot be
  delegated to you.
- Before editing any file matched by the policy's `[meta] paths` (the policy
  itself, trust registries, CI workflows, branch-protection artifacts), you
  MUST surface the change to your human operator rather than pushing it
  through — these files are the root of trust and carry their own required
  level (spec §5.4). Read `.semver-trust/policy.toml` to know which paths
  those are.

## The block you emit

The final paragraph of every commit message you author:

```text
Provenance: agent
Provenance-Agent: <your-tool>/<version>
Provenance-Model: <model-identifier>
```

`Provenance-Model` is optional but honest; emit it when you know it. For
mixed human/agent authorship, `Provenance: mixed` with the same
`Provenance-Agent` line. A `Co-authored-by:` line, if your tooling adds one,
is corroborating evidence only — it never substitutes for the `Provenance:`
trailer (spec §4.1). Full grammar:
[trailers reference](../reference/trailers.md).

## Commit mechanics

Compose the message with the block inline, or attach it with `--trailer`:

```sh
git commit -m "feat: parse adoption boundary" \
  -m "Provenance: agent
Provenance-Agent: claude-code/<version>
Provenance-Model: <model-id>"
```

If you authored a commit and the block is missing or wrong, fix it **before**
it leaves the machine (amending re-signs):

```sh
git commit --amend --no-edit --trailer "Provenance: agent" \
  --trailer "Provenance-Agent: claude-code/2.8"
```

Never amend commits already on a shared branch; report the problem to your
operator instead.

You do not need a signing identity of your own: commits you author are
normally signed by your operator's key, and that is correct under the scheme —
the signature records who is accountable for the commit entering history; your
trailer records who wrote it (spec repository ADR-025 makes this split
explicit). If the repository gives you a dedicated signing identity, use it;
never manufacture one.

## Why honesty pays

The scheme is built so that truthful trailers dominate every alternative:

- An honestly-trailered agent commit plus **one** signed human review — even
  by the same identity that signed your commit — classifies at **T2**
  (ADR-025). Your work reaches the clean release channel through exactly one
  human's accountability.
- A commit that claims `human` under a machine-attributable signature, or
  carries no trailer where policy requires one, classifies as **ambiguous** —
  the weakest class, flooring its whole scope at T0 until reviewed
  (spec §3.2).

Lying costs the repository more than honesty ever could, and verification
reads what actually entered history, not what anyone intended.

## When verify aborts on your commit

An abort is not a low score — it means something could not be verified at all
([abort vs T0](../reference/verify-output.md#abort-vs-t0--the-distinction-that-matters)).
If the failing commit is yours: don't retry, don't work around the
verification, and don't touch the trust material. Read the one-line reason
(unknown signer, missing policy, malformed registry), report it to your
operator with the failing step, and stop. Fail-closed behavior is the system
working.

## Repository-specific overrides

The repository's own agent contract — `AGENTS.md` at the root, or whatever
its `CLAUDE.md` points at — is binding and **wins wherever it is stricter**.
This page is the floor, not the ceiling: a repository may forbid things this
contract permits (this one, for instance, requires a `Refs:` trailer on
work-item commits and forbids `Co-authored-by:` entirely). Read the local
contract first; apply both.
