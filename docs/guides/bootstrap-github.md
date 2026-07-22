<!-- SPDX-License-Identifier: Apache-2.0 -->
# Bootstrapping a new GitHub repository under SemVer-Trust

This guide takes an empty directory to a verified, promotable first release. The
**local** command blocks were executed as written, in order, with real output;
the **GitHub-side** steps (creating the repository, importing rulesets, repo
settings — §5) touch a real account and are shown representatively. You'll need
git, `ssh-keygen`, the `semver-trust` binary
([install](../../README.md#install)), and — for the GitHub steps — the
[`gh` CLI](https://cli.github.com); background concepts are in
[concepts](../concepts.md).

Greenfield is the easy case, and it's worth savoring why: **your history is
verifiable from commit #1**, so the adoption-boundary machinery that legacy
repositories reach for ([adopting on an existing repository](adopt-legacy-github.md))
never applies to you, and if you never merge through GitHub's web UI you never
need GitHub's web-flow key in your keyring at all.

## 1. Two keys, for two purposes

Two keys with different jobs: a **commit-signing key** (signs your work) and a
*separate* **attestation key** (signs your accountability statements — reviews
and releases). The [two-key model](../reference/trust-material.md#two-keys-two-purposes)
explains why they must not be one key — and the tools enforce it (`enroll`,
`setup`, and `doctor` all refuse a key enrolled for both).

**The commit-signing key is your normal git signing identity — reuse the one you
already have** (the key on your GitHub account, or whatever you already sign
commits with); there is no need to mint a new one per repository. Find it:

```sh
git config --get user.signingkey             # already signing? this is your key
ls -1 ~/.ssh/*.pub                           # SSH public keys on this machine
gpg --list-secret-keys --keyid-format long   # GPG keys (the id after ed25519/ or rsa4096/)
```

Only generate a commit key if you don't have one:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/semver-trust-commit -C 'alex@example.com commit signing'
```

**The attestation key is always a fresh, dedicated SSH key** — it must be distinct
from your commit key (ADR-022), and attestations are always OpenSSH SSHSIG, never
GPG. Generate it regardless of how you sign commits:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/semver-trust-attest -C 'semver-trust attestation signing'
```

> **Using GPG for commit signing?** Reuse (or generate) an OpenPGP key for your
> commits — SemVer-Trust verifies GPG-signed history just as well
> ([GPG-signed history](../reference/trust-material.md)). Find its id with
> `gpg --list-secret-keys --keyid-format long`, or generate one with
> `gpg --quick-generate-key "Alex Doe <alex@example.com>" ed25519 sign`. §2 shows
> the GPG commit-signing setup; the attestation key above stays SSH regardless.

## 2. Trust material in the very first commit

Verification reads trust material **from the tree of the commit being
verified** — which means the first commit can carry its own roots, and your
repository is verifiable from inception. Create the repository and the
`.semver-trust/` directory, and write the policy that names your registries:

```sh
git init -b main widget && cd widget
git config user.name "Alex Doe"
git config user.email alex@example.com
mkdir .semver-trust
```

The minimal single-maintainer policy — `threshold = "T2"` because T2 is what
one accountable human can honestly produce, and `required_level = "T2"` on the
meta-paths so you can never lock yourself out (the full reasoning:
[choosing threshold and strategy](../reference/policy.md#choosing-threshold-and-strategy)).
`.github/rulesets/**` is in `[meta].paths` from the founding commit even though
those files arrive in §5: they *are* the platform root of trust, so the commit
that introduces them — and every later edit the drift check treats as
authoritative — must itself reach `required_level`, not sneak in at T0:

```sh
cat > .semver-trust/policy.toml <<'EOF'
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths = [
  ".semver-trust/**",
  ".github/workflows/**",
  ".github/rulesets/**",
]
required_level = "T2"

[identity]
attestation_signers = ".semver-trust/attestation_signers"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"

[trailers]
require = true

[graph]
adapter = "none"
EOF
```

Now enroll your two keys into the registries the policy names. `semver-trust
enroll` generates the byte-exact registry line and appends it under an atomic
writer — you never hand-type it (shell quoting eats `namespaces="…"`, and the two
namespaces must never be transposed):

```sh
semver-trust enroll --commit-key ~/.ssh/semver-trust-commit.pub --write
semver-trust enroll --attest-key ~/.ssh/semver-trust-attest.pub --write
```

```text
alex@example.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL29blAq66u/Q8A7f5sVxnIr0KqPYaRzWzbqC6yUICxF

principal: alex@example.com (from git user.email)
--commit-key → .semver-trust/allowed_signers  (fingerprint SHA256:7YWX28qJKoJVD0RBuQxH0dsBdy55ktTRuQF7BKLYPME)

wrote .semver-trust/allowed_signers — now commit it: git add .semver-trust && git commit -S
```

The namespaces (`git` for commit signing, `attestation@semver-trust.dev` for
attestations) come from compiled-in constants, so they can never be mistyped, and
enroll refuses to put one key in both registries — the two keys must stay distinct
(ADR-022). The raw registry line prints on stdout; all guidance is on stderr.
([Registry formats](../reference/trust-material.md); the two different namespaces
are the point.)

### Using a GPG key for commit signing instead

If your commits are GPG-signed rather than SSH-signed, make three substitutions
to the SSH steps above — do them *instead of*, not in addition to. The
attestation key stays SSH regardless (attestations are always SSHSIG, ADR-022),
so `semver-trust enroll --attest-key … --write` is unchanged.

1. **In the policy, replace the `[identity.human]` block** — a `gpg_keyring` in
   place of `allowed_signers` (a keyring, not an SSH registry). The rest of the
   policy is identical:

   ```toml
   [identity.human]
   gpg_keyring = ".semver-trust/gpg-keyring.asc"
   ```

2. **Skip `enroll --commit-key`** (that enrolls an SSH commit key). Export your
   **public** key to a file and enroll *that* into the keyring instead — `enroll`
   refuses private-key material and prints the identities it adds:

   ```sh
   gpg --armor --export <YOUR-GPG-KEY-ID> > dev.asc   # find it: gpg --list-secret-keys --keyid-format long
   semver-trust enroll --gpg-pubkey dev.asc --write
   ```

3. **In `setup` (next step), pass `--gpg-signing-key <YOUR-GPG-KEY-ID>`** in place
   of `--signing-key`.

The verifier defaults `--gpg-keyring` from the policy path, so GPG-signed commits
verify with no extra flags — exactly as SSH-signed ones do.

## 3. Configure git, then make the founding commit

Add the commit template (the human trailer default — agents author theirs
explicitly; see [the shared-machine model](../reference/trailers.md#one-machine-two-authors-humans-and-agents-side-by-side)),
then let `semver-trust setup` wire this clone's git in one command:

```sh
printf 'Provenance: human\n' > .gitmessage
semver-trust setup --signing-key ~/.ssh/semver-trust-commit.pub
```

```text
setup: repo ~/widget  gitdir .git  git /opt/homebrew/bin/git  remote origin ((no url))

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

`setup` runs **after** the policy, registries, and `.gitmessage` exist — so
`commit.template` and `gpg.ssh.allowedSignersFile` bind to real files — and
**before** the first commit, so that commit is signed and trailered. It writes
repo-local config only (never `--global`; for a GPG commit key use
`--gpg-signing-key <YOUR-GPG-KEY-ID>` instead). It installs **no** hook — enable
the committed [commit-msg hook](../reference/trailers.md#the-commit-msg-hook)
yourself, once, with `git config core.hooksPath .githooks`.

Make the founding commit — path-scoped, so the adoption reads as a pure
accountability act:

```sh
git add .semver-trust .gitmessage
git commit -m "chore: adopt semver-trust" -m "Provenance: human"
```

Two ordering invariants make that founding commit clean — both about
*sequence*, not content:

- **Signing and the trailer template are configured before it** (what
  `semver-trust setup` did above). An unsigned or untrailered first commit isn't fatal,
  but it is the one mistake that recreates on day one the adoption-boundary
  problem greenfield exists to avoid — and while the repository is still
  unshared, `git rebase`-and-resign is the clean recovery (rewriting history is
  only off-limits once a branch is shared or protected).
- **It carries trust material alone** — `git add .semver-trust .gitmessage`,
  never `git add -A`. The adoption and enrollment commits are what outside
  reviewers re-derive later, so they should read as pure accountability acts,
  not code changes with the trust material buried inside.

Sanity-check the environment immediately. `semver-trust doctor` runs the
read-only checks that surface, now, what verification would later abort or
mis-price — and ends by printing the exact `verify` invocation it preempts:

```text
semver-trust doctor — persona: maintainer

  PASS  config/git-binary               git binary: /opt/homebrew/bin/git
  PASS  config/signing-enabled          commit signing enabled
  PASS  policy/parse                    policy parses; matches HEAD
  PASS  registry/principal-enrolled     alex@example.com is enrolled in allowed_signers
  PASS  keys/attestation-distinct       commit signing key is distinct from the attestation keys
  PASS  policy/meta-coverage            meta-paths cover the policy, registries, and CI workflows
  PASS  keys/sign-roundtrip             signing key round-trips (signs + verifies a compiled-in constant)
  PASS  remote/fetch-refspec            attestation fetch refspec is configured
  …

next, run the gate doctor preempts:
  semver-trust verify --repo . --to HEAD
```

The policy itself is validated the same way — its digest and the §6.4 decision
table in effect:

```console
$ semver-trust policy validate --repo .
policy .semver-trust/policy.toml is valid (schema 0.1)
digest:      sha256:ac8f26074370ef7b2d0e850d7a716ca801af2c9b8991d690f19e7959d5499dd5
threshold:   T2
strategy:    demote
...
$ semver-trust policy explain --repo .   # the §6.4 decision table in effect
```

## 4. Work, and verify early

Normal development follows — signed, trailered commits. Here, one human
commit and one agent commit (the agent block authored explicitly, per the
[agent contract](agent.md)):

```sh
echo 'package widget' > widget.go
git add widget.go && git commit -m "feat: widget core" -m "Provenance: human"

echo 'package widget // v2' > widget.go
git add widget.go && git commit -m "feat: widget frobnicator" -m "Provenance: agent
Provenance-Agent: claude-code/<version>
Provenance-Model: <model-id>"
```

Run `verify` whenever you like — it's read-only and fast. `--from ''` means
"first release: walk from the root." The `--verify-time` is the injected
clock; pick any instant that post-dates your commits (verification must never
depend on the wall clock — [why](../reference/verify-output.md)):

```console
$ semver-trust verify --repo . --from '' --to HEAD --verify-time 2026-07-13T00:00:00Z

[§10 steps 2–3] commits
  SHA      LEVEL  AUTHORSHIP  REVIEW  SIGNER
  9a3998e  T0     agent       none    alex@example.com
  6457e88  T2     human       none    alex@example.com
  db0f152  T2     human       none    alex@example.com

[§10 step 5] own trust (per scope)
  default: T0  (commits: 9a3998e, 6457e88, db0f152)
```

Read that honestly: the unreviewed agent commit is T0, and weakest-link
flooring makes the whole scope T0. Nothing is wrong — this is the system
telling you what evidence exists so far.

## 5. Create the GitHub repository, then harden it

Everything so far is local. Create the repository on GitHub and push `main` to
it. One wrinkle from the order of these steps: `semver-trust setup` (§3) already
created a local `origin` — the attestation fetch refspec, with **no URL yet**
(`remote origin ((no url))` in its output above). So you point *that* remote at
the new repository; `gh repo create --source=. --remote=origin` would run `git
remote add origin` under the hood and fail with `Unable to add remote "origin"`.

```sh
gh repo create <owner>/widget --private          # create the empty repo (--public for an open project)
git remote set-url origin https://github.com/<owner>/widget.git   # point setup's origin at it — not `remote add`
git config --add remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*'   # the branch refspec setup didn't add
git push -u origin main
```

`set-url` (not `remote add`) because `origin` already exists; the extra fetch
refspec restores branch tracking — `setup` added only the attestation refspec, so
without this line `git fetch` would pull attestations but not branches. Without
`gh`: create an empty repository in the GitHub UI, then run the same three git
commands (swap in the SSH URL `git@github.com:<owner>/widget.git` if that is your
remote protocol). The command blocks in this section touch a real GitHub account,
so — unlike the local steps above — they are shown representatively; adapt the
owner, name, and visibility to yours.

### Register your commit key with GitHub

GitHub marks a commit **Verified** only when the *account* carries its public key
as a **signing** key — and the history-integrity ruleset below rejects every commit
whose signature GitHub cannot verify. SemVer-Trust enrollment (§2) taught your
*local* verifier to trust the key; it tells GitHub nothing. Register it once, as a
signing key (this is separate from any authentication key —
[GitHub's signing-key docs](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account?tool=cli)):

```sh
gh ssh-key add ~/.ssh/semver-trust-commit.pub --type signing --title "semver-trust commit signing"
```

For a GPG commit key, `gh gpg-key add <exported-public-key>.asc` instead. A key
GitHub already shows as Verified on your commits (the reuse path in §1) needs
nothing here. Skip this on the fresh-key path and the first push after the ruleset
import is rejected — the platform rule doing its job.

### Protect the branch

Verification assumes the history on `main` is signed and unrewritten and that
meta-path changes were reviewed — but only the *platform* enforces that between
pushes. This repository commits its branch protection as two importable rulesets
([.github/rulesets/README.md](../../.github/rulesets/README.md)); they target
`~DEFAULT_BRANCH`, so they drop into any new repository unchanged.

> **Plan prerequisite:** rulesets on a **private** repository require a paid plan
> (Pro, Team, or Enterprise Cloud); GitHub Free offers them only on **public**
> repositories
> ([ruleset availability](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)).
> On Free with a private repo, make the repo public, upgrade, or fall back to
> classic branch protection (Settings → Branches — configured by hand, not
> imported from these JSON files, and without the merge-method restriction).

Commit the rulesets (trust-sensitive config — path-scope the add), push, and
import:

```sh
mkdir -p .github/rulesets    # then copy the two branch-main-*.json files in
git add .github/rulesets && git commit -m "chore: branch rulesets" -m "Provenance: human"
git push origin main
gh api repos/<owner>/widget/rulesets --input .github/rulesets/branch-main-history-integrity.json
gh api repos/<owner>/widget/rulesets --input .github/rulesets/branch-main-review-gate.json
```

(Or in the UI: **Settings → Rules → Rulesets → New ruleset → Import a
ruleset**.) `scripts/check-rulesets.py` compares the live rulesets against these
files and fails on drift, so the committed JSON stays the source of truth. The
two split by bypass policy:

- **History integrity** — no force-push, no deletion, **signed commits
  required**; bypass for nobody. The verifiable history is absolute.
- **Review gate** — a pull request required, merge commits only, required checks
  `ci` and `commit-hygiene`; bypass for the **Admin** role, so you can push a
  locally-created signed merge while the bypass-less history rules still bind
  every commit.

**Solo note:** the review gate's `required_approving_review_count` is **0** — a
PR is required, but a GitHub *approval* is not, because your trust signal is a
**signed review attestation** (`attest review`, §8), not the green checkmark. As
the sole maintainer you review your own agent-assisted work to T2 (spec
repository ADR-025), and the Admin bypass lets you push the signed merge.
Confirm both imports took effect — a test push the rules reject is the
confirmation.

### Merge and Actions settings

- **Merge commits only** (Settings → General → Pull Requests): allow merge
  commits, **disable squash and rebase merging**. A web-UI merge is signed by
  GitHub's key, not yours — so merge on your machine, signed and trailered, then
  push; a small script like this repository's
  [`scripts/merge-pr.sh`](../../scripts/merge-pr.sh) keeps it one command. This
  is why the policy above leaves `[identity.agent] bot_accounts` **unset**: with
  no web-UI merges there is no `noreply@github.com`-signed commit to classify.
  If you *will* use the merge button, add it and enroll GitHub's web-flow key
  ([adopting on an existing repository §3](adopt-legacy-github.md#3-the-web-flow-key-specifically)).
- **Enable GitHub Actions** (Settings → Actions → General) so the verify and
  commit-hygiene checks below run on pull requests; a release workflow, if you
  add one, needs `contents: write` and — for keyless cosign — `id-token: write`.
- **No history rewriting on `main`, ever** — verification walks that history.
  Keep "require linear history" *off*: this repository is merge-commits-only.

## 6. CI

Wire the composite verify action
([usage and inputs](../../.github/actions/semver-trust-verify/README.md)) in
**informational mode first** — it reports honestly on every PR without
failing jobs — and flip it to enforced once your first release exists. Add a
commit-hygiene check (signature + trailer presence on PR commits) so
contributors learn about problems at PR time, not release time.

## 7. The first release ceremony

Cut the release exactly as the evidence stands. `--dry-run` first, always:

```sh
semver-trust release --repo . --from '' --to HEAD \
  --claimed-bump minor --blast low \
  --tag-key ~/.ssh/semver-trust-attest --attest-key ~/.ssh/semver-trust-attest \
  --verify-time 2026-07-13T00:00:00Z --dry-run
```

Then for real. At effective T0 under `demote`, the §6.4 table sends the
release to the trust pre-release channel:

```console
$ semver-trust release ... (same flags, without --dry-run)
tag v0.1.0-t0.1 -> 9a3998e1e4e916dc7f1960c5cb3bee83df55076c (signed annotated, SSHSIG namespace "git")
release attestation https://semver-trust.dev/release/v0.1
  stored: refs/attestations/9a3998e1e4e916dc7f1960c5cb3bee83df55076c/ca30af04bf918ae4d3c515e7
          refs/attestations/v0.1.0-t0.1/ca30af04bf918ae4d3c515e7
```

**A `-t0.1` first release is the system working**, not failing: the version
says "final content, zero accountable humans in evidence, opt in knowingly."
Publish it — tag, branch, and the attestation refs (which don't travel unless
you name them — [why](../reference/attestation-refs.md)):

```sh
git push origin main --tags
git push origin 'refs/attestations/*:refs/attestations/*'
```

`semver-trust setup` already set the fetch refspec (§3), so every later `git
fetch`/`pull` in this clone pulls new evidence automatically — the push side
stays an explicit command ([why](../reference/attestation-refs.md#moving-them)).
A fresh clone that hasn't run `setup` can add it directly:

```sh
git config --add remote.origin.fetch 'refs/attestations/*:refs/attestations/*'
```

## 8. Review, then promote — same commit, clean channel

Now add the missing evidence: your signed review of the range (yes, reviewing
your own agent's work counts as the *one* accountable human — spec repository
ADR-025):

```sh
semver-trust attest review --repo . --from '' --to HEAD \
  --reviewer alex@example.com --verdict approved \
  --pr https://github.com/you/widget/pulls \
  --key ~/.ssh/semver-trust-attest --store
git push origin 'refs/attestations/*:refs/attestations/*'
```

`promote` re-decides the *same commit* under the new evidence and, if it now
clears the threshold, cuts the clean tag — no rebuild, no new source:

```console
$ semver-trust promote --repo . --tag v0.1.0-t0.1 \
    --tag-key ~/.ssh/semver-trust-attest --attest-key ~/.ssh/semver-trust-attest \
    --verify-time 2026-07-13T00:00:00Z
  effective:      T2 (own T2)
  supersedes:     refs/attestations/9a3998e.../ca30af04bf918ae4d3c515e7
tag v0.1.0 -> 9a3998e1e4e916dc7f1960c5cb3bee83df55076c (signed annotated, SSHSIG namespace "git")
release attestation https://semver-trust.dev/release/v0.1 (supersedes the prior decision, §8.1)
```

Note the SHA: identical to `v0.1.0-t0.1`. Push the new tag and refs. (Run
`promote` *before* new evidence exists and it refuses — "evidence has not
changed the decision" — promotion is never a re-cut.)

## 9. Prove it like an outsider

The claim that matters: anyone, from public material alone, re-derives your
decision. Verified here in a fresh clone:

```console
$ git clone <your-remote> fresh && cd fresh
$ git fetch origin 'refs/attestations/*:refs/attestations/*'
$ semver-trust verify --repo . --from '' --to v0.1.0 --verify-time 2026-07-13T00:00:00Z

[§10 steps 2–3] commits
  SHA      LEVEL  AUTHORSHIP  REVIEW          SIGNER
  9a3998e  T2     agent       human_distinct  alex@example.com
  6457e88  T2     human       none            alex@example.com
  db0f152  T2     human       none            alex@example.com
```

The agent commit now reads T2 — authored by an agent, stood behind by a
human, cryptographically, reproducibly. Use the `--verify-time` recorded in
the release attestation (`predicate.timestamp`) so the reproduction holds
forever, key expiries notwithstanding.

That's the full loop. From here, each release repeats §7–§9 — with
`--from <previous-tag>` on the default v0.3 path, or, on the opt-in v0.10 path,
with a `--bootstrap-descriptor` and no `--from` at all: the accepted chain head is
auto-detected, so the version predecessor is *authenticated* rather than typed
(spec ADR-027/029). This repository's own
[release runbook](../release-runbook.md) is the living example of the
repeatable cadence.
