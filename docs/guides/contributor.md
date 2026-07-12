<!-- SPDX-License-Identifier: Apache-2.0 -->
# Working in a repository that uses SemVer-Trust

You've been asked to contribute to a repository that follows SemVer-Trust.
This guide is your day-to-day: what changes about your workflow, the ten
minutes of one-time setup, and what to do when something is rejected. It
assumes you know git; for *why* any of this exists, read
[concepts](../concepts.md) — the short version is that releases here carry
cryptographic evidence of who stands behind them, and that evidence is
assembled from ordinary commits like yours.

## What changes for you

Four things, and only the first two touch your daily flow:

1. **Every commit is signed.** Signature verification is how the scheme knows
   a commit came from you and not from something wearing your name.
2. **Every commit carries a `Provenance:` trailer** declaring who authored it —
   you, an agent, or both. One line at the end of the commit message.
3. **Merges are created by a maintainer, locally and signed** — not by the
   platform's merge button (a web-UI merge is signed by the platform's key,
   not a person's). Your PR is still a normal PR; only the final click is
   different.
4. **Releases may ship as trust pre-releases** (`v1.4.0-t1.1`). That's the
   honest channel for under-evidenced releases, not a build failure — see
   [the last section](#when-a-release-ships-as--t11).

## One-time setup

Configure SSH commit signing and the repository's commit template (all local
to the repo unless you `--global` it):

```sh
# A signing key, if you don't already have one
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_signing -C 'you@example.com commit signing'

# Sign every commit with it
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519_signing.pub
git config commit.gpgsign true

# The repository's trailer template (pre-fills Provenance: human)
git config commit.template .gitmessage
```

Optionally install the
[commit-msg hook](../reference/trailers.md#the-commit-msg-hook) so a missing
trailer can never leave your machine.

To see verification locally, point git at the repository's signer registry —
until you do, `git log --format='%G?'` reports an error rather than a
verdict:

```sh
git config gpg.ssh.allowedSignersFile .semver-trust/allowed_signers
git log -1 --format='%G? by %GS'     # → G by you@example.com, once enrolled
```

## The trailer on every commit

Your commits end with one line:

```text
Provenance: human
```

If an agent wrote part of the change, say so — `Provenance: agent` or
`Provenance: mixed` with the tool named in `Provenance-Agent:`. The full
grammar, the template, and the honesty rules live in the
[trailers reference](../reference/trailers.md); the one mechanical gotcha
worth repeating is that **`git commit -m` bypasses the template**, so either
commit interactively or add the trailer explicitly:

```sh
git commit -m "fix: reject empty policy keys" --trailer "Provenance: human"
```

## Getting your key enrolled

Your signatures count once your key is in the repository's signer registry.
Send a maintainer your *public* key, or open the PR yourself: one line in
`.semver-trust/allowed_signers`,

```text
you@example.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

That PR is not paperwork — the maintainer merging it is asserting "this
identity's signatures now count," which is why the registry sits behind the
policy's meta-path gate. Details and the removal semantics are in
[trust material](../reference/trust-material.md).

## When you forget

**Forgot to sign or trailer, caught before pushing** — amend (this re-signs):

```sh
git commit --amend --no-edit --trailer "Provenance: human"
```

**Caught by CI on your PR** — the repository's hygiene check names the commit;
amend or rebase the offending commits on your branch and force-push *your own
branch* (never a shared one).

**Slipped into history anyway** — it isn't fatal, it's priced: an untrailered
or claim-contradicting commit classifies as *ambiguous*, the weakest
authorship class, and floors its scope at T0 until a signed review lifts it
(spec §3.2). The fix at that point is a maintainer's post-hoc review
attestation, not history surgery.

## Sharing your machine with an agent

If a coding agent works from your checkout, your commits and its commits must
carry different trailers — and the mechanics keep them apart without your
attention: the template pre-fills `Provenance: human` only in your interactive
editor, while a well-behaved agent writes its own `Provenance: agent` block
explicitly and never sees the template (agents commit with `-m`/`-F`, which
skip it). Both kinds of commit may be signed by your key; the trailer, not
the signature, is the authorship claim. The full model — including the
optional per-checkout config split and the enforcing hook — is in the
[trailers reference](../reference/trailers.md#one-machine-two-authors-humans-and-agents-side-by-side);
the agent's own obligations are in the [agent contract](agent.md).

When you review what an agent produced on your machine, check the trailer
first: an agent commit claiming `Provenance: human` is the one thing you
should never let through — honesty is the property the whole scheme prices.

## Reviews, and reviewing yourself

Platform approvals (the green checkmark) are not what counts here. A review
that affects trust is a **signed review attestation** — a maintainer runs
`semver-trust attest review` over a range and signs it with an enrolled
attestation key (spec §4.3). As a contributor you don't need to do this;
know that it exists, because it's what turns your reviewed work into T2/T3
releases.

One rule surprises people (spec repository ADR-025): reviewing *your own*
agent-assisted work counts. The self-review exclusion stops one human from
counting as **two** (T3 always needs a second person), never from counting as
**one** — so a maintainer's signed review of commits their own agent authored
honestly yields T2. You can be the one accountable human for your agent's
work; you can never be two.

## Reading verify output on your PR

When a verify report names your commit, three shapes cover almost everything:

| You see | It means | You do |
|---|---|---|
| Your commit at the level you expected | Classified as intended | Nothing |
| `Error: §10 step 3 ... unknown signer` naming your commit | Your key isn't enrolled (or you signed with a different one) | Enrollment PR, or re-sign |
| Your commit at a *lower* level than expected | Trailer missing/contradicted, or review not yet attested | Amend if unpushed; otherwise a maintainer review lifts it |

The full anatomy of the report — own vs effective trust, and why an *abort*
is not a *low level* — is in
[reading verify output](../reference/verify-output.md).

## When a release ships as `-t1.1`

A release tagged `v1.4.0-t1.1` is telling consumers: "this content is final,
one accountable human short of the clean bar; opt in knowingly." Default
resolvers skip it, evidence can accumulate, and a later signed review promotes
the *same commit* to `v1.4.0` — no rebuild, no new source (spec §7.3). If
your commit is the reason a release demoted, the table above tells you which
kind of fix applies.
