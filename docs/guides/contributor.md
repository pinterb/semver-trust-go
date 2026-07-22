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

You sign commits with an SSH or GPG key. **If you already have one — the key on
your GitHub account, or whatever you already sign commits with — reuse it; there
is no need to mint a new key per repository.** Find it:

```sh
git config --get user.signingkey             # already signing? this is your key
ls -1 ~/.ssh/*.pub                           # SSH public keys on this machine
ssh-add -L                                   # keys currently loaded in your agent
gpg --list-secret-keys --keyid-format long   # GPG keys (the id after ed25519/ or rsa4096/)
```

Only generate a fresh key if you don't have one:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/semver-trust-commit -C 'you@example.com commit signing'
```

`semver-trust setup` then wires **this clone's git** to whichever key you chose —
repo-local config only, never `--global`, never the working tree. Point it at
your SSH public-key path, or pass a GPG key id:

```sh
semver-trust setup --signing-key ~/.ssh/semver-trust-commit.pub   # or YOUR existing .pub
# for a GPG signing key instead:  semver-trust setup --gpg-signing-key <YOUR-GPG-KEY-ID>
```

```text
setup: repo ~/project  gitdir .git  git /opt/homebrew/bin/git  remote origin (https://github.com/acme/project.git)

  set      gpg.format = ssh
  set      user.signingkey = ~/.ssh/semver-trust-commit.pub
  set      commit.gpgsign = true
  set      commit.template = .gitmessage
  set      gpg.ssh.allowedSignersFile = .semver-trust/allowed_signers
  add      remote.origin.fetch += refs/attestations/*:refs/attestations/*

applied. to reverse this setup:
  git config --unset gpg.format
  git config --unset user.signingkey
  git config --unset commit.gpgsign
  git config --unset commit.template
  git config --unset gpg.ssh.allowedSignersFile
  git config --unset remote.origin.fetch "refs/attestations/\*:refs/attestations/\*"
```

That one command sets SSH commit signing (`gpg.format`, `user.signingkey`,
`commit.gpgsign`), the repository's trailer template (`commit.template`, so an
interactive commit pre-fills `Provenance: human`), the local signer registry
(`gpg.ssh.allowedSignersFile`, so `git log --format='%G?'` gives a verdict
instead of an error), and the attestation-ref fetch refspec (so every
`git fetch`/`pull` carries release and review evidence automatically — non-force,
because those refs are content-addressed and append-only,
[attestation refs](../reference/attestation-refs.md)). Its first line names the
exact `git` it ran and it ends with the commands that reverse it, so nothing is a
mystery; `--dry-run` prints the `git config` commands without running any. If a key
is already set to a different value it refuses rather than clobber it — pass
`--force` for the non-identity keys (never for `user.signingkey`).

`setup` deliberately does **not** install the commit-msg hook — a trust tool
should not write executable code that runs on your every commit. Enable the
committed [commit-msg hook](../reference/trailers.md#the-commit-msg-hook) yourself,
once, so a missing trailer can never leave your machine:

```sh
git config core.hooksPath .githooks
```

`semver-trust doctor` confirms the wiring at any point (and, until your key is
enrolled below, tells you exactly that):

```text
semver-trust doctor — persona: contributor
  …
  WARN  registry/principal-enrolled     dana@example.com is not yet enrolled in allowed_signers (expected until your enrollment PR merges)
  WARN  keys/configured-vs-enrolled     configured signing key is not enrolled in allowed_signers (expected until your enrollment PR merges)
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
`semver-trust enroll` generates the exact registry line — you never hand-type it
(shell quoting silently eats `namespaces="git"`, and a mistyped namespace is a
signature that never verifies):

```sh
semver-trust enroll --commit-key ~/.ssh/semver-trust-commit.pub
```

```text
dana@example.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKWHj9drnStLr+/FPTXapx7TWea4XaFcR5V2YPSjY2hX

principal: dana@example.com (from git user.email)
--commit-key → .semver-trust/allowed_signers  (fingerprint SHA256:e9h6qGNgJPV26/o79D0KPM1HL5VKWO/K4EqE6T6THGo)
```

The first line — raw registry bytes on stdout — is what goes in the PR; the
guidance below it prints on stderr. The principal defaults to your `git
user.email`, so the registry identity equals your commit identity by
construction. Open a PR adding that one line to `.semver-trust/allowed_signers`
(or send a maintainer your *public* key) — `--write` appends it for you under an
atomic writer, but it never stages, commits, or signs; the accountability act
stays your signed commit.

**Signing commits with GPG instead?** Enroll your armored *public* key into the
repository's keyring rather than the SSH registry — this works only where the
policy declares a `gpg_keyring` under `[identity.human]` (check
`.semver-trust/policy.toml`, or ask a maintainer; `enroll` refuses if it is
absent). Your commit key's family must match what the repository accepts:

```sh
gpg --armor --export <YOUR-GPG-KEY-ID> > you.asc   # find the id: gpg --list-secret-keys --keyid-format long
semver-trust enroll --gpg-pubkey you.asc
```

`enroll` prints the fingerprint and the identities it adds, refuses private-key
material, and (with `--write`) appends to the keyring the policy names.

That enrollment PR — SSH or GPG — is not paperwork: the maintainer merging it is
asserting "this identity's signatures now count," which is why the registry sits
behind the policy's meta-path gate. Details and the removal semantics are in
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
resolution defers it the way it defers any pre-release (subject to each
ecosystem's rules), evidence can accumulate, and a later signed review promotes
the *same commit* to `v1.4.0` — no rebuild, no new source (spec §7.3). If
your commit is the reason a release demoted, the table above tells you which
kind of fix applies.
