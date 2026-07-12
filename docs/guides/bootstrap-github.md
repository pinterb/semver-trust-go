<!-- SPDX-License-Identifier: Apache-2.0 -->
# Bootstrapping a new GitHub repository under SemVer-Trust

This guide takes an empty directory to a verified, promotable first release.
Every command block was executed as written, in order, and the output shown is
real. You'll need git, `ssh-keygen`, and the `semver-trust` binary
([install](../../README.md#install)); background concepts are in
[concepts](../concepts.md).

Greenfield is the easy case, and it's worth savoring why: **your history is
verifiable from commit #1**, so the adoption-boundary machinery that legacy
repositories reach for (the legacy-adoption guide, forthcoming in this docs set)
never applies to you, and if you never merge through GitHub's web UI you never
need GitHub's web-flow key in your keyring at all.

## 1. Generate two keys, for two purposes

A commit-signing key (signs your work) and a *separate* attestation key (signs
your accountability statements — reviews and releases). The
[two-key model](../reference/trust-material.md#two-keys-two-purposes) explains
why they must not be one key.

```sh
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_signing -C 'alex@example.com commit signing'
ssh-keygen -t ed25519 -f ~/.ssh/semver-trust-attest -C 'semver-trust attestation signing'
```

## 2. Trust material in the very first commit

Verification reads trust material **from the tree of the commit being
verified** — which means the first commit can carry its own roots, and your
repository is verifiable from inception. Create the repository and the
`.semver-trust/` directory before anything else:

```sh
git init -b main widget && cd widget
git config user.name "Alex Doe"
git config user.email alex@example.com
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519_signing.pub
git config commit.gpgsign true

mkdir .semver-trust
printf '%s namespaces="git" %s\n' alex@example.com \
  "$(cut -d' ' -f1,2 ~/.ssh/id_ed25519_signing.pub)" \
  > .semver-trust/allowed_signers
printf '%s namespaces="attestation@semver-trust.dev" %s\n' alex@example.com \
  "$(cut -d' ' -f1,2 ~/.ssh/semver-trust-attest.pub)" \
  > .semver-trust/attestation_signers
```

([Registry formats](../reference/trust-material.md); note the two different
namespaces — that separation is the point.)

## 3. Write the policy

The minimal single-maintainer policy — `threshold = "T2"` because T2 is what
one accountable human can honestly produce, and `required_level = "T2"` on the
meta-paths so you can never lock yourself out (the full reasoning:
[choosing threshold and strategy](../reference/policy.md#choosing-threshold-and-strategy)):

```sh
cat > .semver-trust/policy.toml <<'EOF'
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths = [".semver-trust/**", ".github/workflows/**"]
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

Add the commit template (the human trailer default — agents author theirs
explicitly; see [the shared-machine model](../reference/trailers.md#one-machine-two-authors-humans-and-agents-side-by-side)),
then make the founding commit:

```sh
printf 'Provenance: human\n' > .gitmessage
git config commit.template .gitmessage

git add -A
git commit -m "chore: adopt semver-trust" -m "Provenance: human"
```

Sanity-check the policy immediately:

```console
$ semver-trust policy validate --repo .
policy .semver-trust/policy.toml is valid (schema 0.1)
digest:      sha256:f99fd6fe3717fc9a2c3cc6a74b3c99eff8a11cfb8a9fd04b53fd070ad6d80b81
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
Provenance-Agent: claude-code/2.8
Provenance-Model: claude-fable-5"
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

## 5. GitHub hardening

Before the repository is shared, protect the branch so the platform can't
undermine what verification assumes. The model this repository uses — two
rulesets as committed JSON artifacts, one for history integrity (no
force-push, no deletion, signatures required; no bypass for anyone) and one
for the review gate (merge commits only, required checks; maintainer bypass
for locally-signed merges) — is documented in
[.github/rulesets/README.md](../../.github/rulesets/README.md), with importable
JSON alongside. Two rules matter most:

- **Merge commits only, created locally.** A web-UI merge is signed by
  GitHub's key, not yours. Merge on your machine, signed and trailered, then
  push — a small script like this repository's
  [`scripts/merge-pr.sh`](../../scripts/merge-pr.sh) (check PR state,
  `git merge --no-ff -S` with trailers, self-verify, push) keeps it one
  command.
- **No history rewriting on `main`, no exceptions** — verification walks that
  history; nothing may edit it.

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

That's the full loop. From here, each release repeats §7–§9 with
`--from <previous-tag>`; this repository's own
[release runbook](../release-runbook.md) is the living example of the
repeatable cadence.
