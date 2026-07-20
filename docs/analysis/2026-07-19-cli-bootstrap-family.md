<!-- SPDX-License-Identifier: Apache-2.0 -->
# CLI Bootstrap Family — Proposal and Adversarial Analysis

- **Date:** 2026-07-19
- **Revised:** 2026-07-20 — corrected for #76 (the v0.10 production wiring,
  merged after the pin below): problem #11 / issue #70 is resolved, and the
  bootstrap descriptor now governs the recurring chain, not only the genesis
  boundary. This is a surgical correctness pass — the `file:line` references
  still point at the original pin and are not re-verified here (a full re-pin
  waits on the proposal advancing to implementation).
- **Status:** Proposal; non-normative — nothing here changes the scheme or the
  implementation except through the repositories' issue, ADR, and conformance
  processes.
- **Specification target:** `semver-trust/spec@58ec2d9` (draft v0.10, the
  conformance pin recorded in `semver-trust-go/conformance/manifest.json`).
- **Implementation target:** `semver-trust/semver-trust-go@71aec5a3ec0d` (the
  basis for the `file:line` references; #76 has since merged to `main`).

This document proposes that the `semver-trust` binary — which every
maintainer, contributor, and agent already installs — help those constituents
bootstrap and diagnose their own environments, replacing the error-prone
manual ceremony in `docs/guides/*.md`. It was produced in four passes:
a catalog of every manual step the guides prescribe; a design for a
five-command family; and then, deliberately, two adversarial passes — a
steelman against the proposal and a corruption/failure-mode analysis of every
mutation surface, grounded in the vendored go-git source. The adversarial
passes changed the proposal materially: two commands were deferred, one was
slimmed, two documentation fixes were pulled ahead of all code, and a
binding writer contract was proposed (§2; an ADR would make it normative). The proposal is presented here in its
post-adversarial form, with the attacks and their dispositions recorded in
§7–§8 so the cuts are auditable.

All `file:line` references are into this repository
(`semver-trust-go@71aec5a3ec0d`) unless prefixed otherwise. go-git claims
are verified against the pinned `go-git/v5 v5.19.1` (`go.mod:9`).

---

## 1. Problem

The persona guides walk three constituents through entirely manual
environment construction: hand-generated keys, registry files authored with
`printf`/`cut` redirects (`docs/guides/bootstrap-github.md:55-60`), a heredoc
policy, six `git config` lines, and refspecs that must be retyped at every
push, fetch, CI job, and clone. The cataloging pass ranked thirteen
error-prone step classes. They do not all fail the same way — some are
verify-time **aborts**, some are silent **demotions or misclassifications**,
some are **operational** evidence and ceremony hazards — but every one of
them surfaces late: the feedback arrives after the bad commit, push, or
release ceremony exists, never while the mistake is being made:

1. **Registry lines hand-authored via `printf` + `cut`**
   (bootstrap-github.md:55-60; contributor.md) — format-sensitive; the
   principal must equal `user.email`; a malformed line aborts verification.
2. **Byte-exact namespace strings** — `namespaces="git"` versus
   `namespaces="attestation@semver-trust.dev"`; the separation is
   load-bearing (`docs/reference/trust-material.md`), and a typo silently
   makes signatures not count.
3. **Two-key separation unenforced** — nothing checks that the commit and
   attestation keys are distinct (ADR-022), or that the attestation key is
   SSH even when commits are GPG-signed.
4. **`gpg-keyring.asc` append hygiene** — armored public material appended by
   hand; a declared-but-empty keyring fails closed.
5. **`bot_accounts` email matching** — must match the platform signer's
   committer identity per platform.
6. **The `refs/attestations/*` refspec** — the single most repeated fragile
   step (bootstrap-github.md:249, :263, :290; the release runbook; the GitLab
   guide); forgetting it strands evidence while tags travel.
7. **`.gitmessage` is bypassed by `git commit -m`/`-F`** — called out in
   three guides; non-interactive commits silently ship untrailered.
8. **The `Provenance:` trailer** must be the final paragraph with exact keys;
   a wrong or misplaced block classifies ambiguous and floors the scope at T0
   (`internal/trust/classify.go:121-152`).
9. **`adoption_boundary` ordering trap** — the boundary-declaring policy
   change is itself a meta-path commit, and the adopt guide warns that
   meta-paths must cover `.semver-trust/**` *before* it lands
   (adopt-legacy-github.md:117); under draft v0.10 the boundary's authority
   is the out-of-band bootstrap descriptor, which the in-policy value must
   match (spec §5.2, §5.4). Policy-pinned by design, no tooling guardrail.
10. **`--verify-time` discipline** — reproduction must reuse the recorded
    `predicate.timestamp`, never the wall clock.
11. **The `--from ''` vs `--from <tag>` derivation edge** (issue #70 — resolved
    by #76's authenticated version ancestry; the pain now remains only on the
    default v0.3 `--from` path).
12. **Ruleset bypass-split subtlety** — committed JSON plus
    `scripts/check-rulesets.py` exist precisely because hand-configuring the
    UI gets this wrong.
13. **Local signed-merge discipline** — `scripts/merge-pr.sh` self-checks
    with a fragile `%G?`/trailer grep.

By failure class: **verify aborts** — #1, #2, #4, the attestation half of #3
(a non-SSH attestation key fails when the attestation is consumed), and a
mis-ordered #9 (§5.4); **silent demotions or misclassifications** — #7 and #8
(absent/misplaced trailer ⇒ ambiguous ⇒ T0 floor, `classify.go:121-132`) and #5
(platform merges classifying as the wrong identity class); **operational
hazards** — the key-reuse half of #3, plus #6 and #10–#13, which strand
evidence or break ceremony without themselves being verify-time aborts
(#12 is *deliberately* outside offline verify and owned by
`check-rulesets.py`).

Steps 1–5 and 7–9 are duplicated across two or more guides. The premise of
this proposal is simple: the binary that will later refuse or misprice these
mistakes can surface them at setup time, with the same code.

## 2. Governing principles

Every design decision below follows from eight lines. The first four are
philosophy; the last four are the adversarial passes' additions.

1. **The tool generates, formats, validates, and configures; the human
   enrolls and commits.** "Adding a line to a registry is not bookkeeping —
   it is the moment a person becomes accountable under the scheme"
   (trust-material.md:99-115). No command in this family ever runs `git add`
   or `git commit`. The accountability act is always a human's signed commit
   through the meta-path gate.
2. **Every diagnostic FAIL is a verify abort moved earlier.** FAIL-severity
   checks call the same functions verification calls — `sshsig.Resolve`
   (`internal/sshsig/allowedsigners.go:203`), `policy.Parse`
   (`internal/policy/parse.go`), `trust.Classify`
   (`internal/trust/classify.go:93`), the trailer parser — and each FAIL
   names the §10 step it preempts. Checks that are not abort mirrors cap at
   WARN. This is an engineering invariant, not a proof — inputs, clocks,
   severity mapping, worktree-vs-tree reads, and wrapper error handling can
   still drift even over shared functions — so it is guarded: every FAIL
   mirror carries a regression test asserting it wraps the same sentinel or
   classification path verify uses (sequencing-gate 1 respected by reuse,
   held by test).
3. **Fail-closed writers.** Every generated registry or policy is re-parsed
   by the verifier's own strict parsers before touching disk. The tool never
   writes trust material it would itself reject.
4. **Print-by-default is the family invariant.** The steelman's load-bearing
   finding (§8, attack 1): where a command prints material to human eyes, it
   *increases* attention at the accountability moment relative to today's
   `printf … >>` redirects, whose output no human ever sees. Where a command
   cannot take that shape, it does not ship in the initial commitment — that
   is what decided `init`'s fate.
5. **The atomic-writer contract** (risk register, §7): key files are created
   `O_EXCL` with the final mode passed at open; registries and other files
   are built in memory, strict-re-parsed, written to a temp file in the same
   directory, fsynced, and renamed into place; `.git/config` is written only
   under git's own `config.lock` protocol; `--dry-run` performs **zero**
   filesystem mutations (no directory creation, no lock, no temp files); an
   interrupted run removes only files it created and never leaves a partial
   live file.
6. **Repo-relative enforcement for every policy-named path, on read and
   write.** The policy's registry paths carry no path validation today
   (`internal/policy/policy.go:165-190`), and verification is only safe
   because it reads them exclusively from git *trees*
   (`internal/verify/tree.go:32-35` — "never the working tree"). The
   commands proposed here move those paths onto the filesystem, which
   creates a traversal surface that must be fenced (§7, EN-1): absolute
   paths and `..` elements are rejected literally — the reject-don't-sanitize
   posture of `attest.validSubject`
   (`internal/attest/store.go:184-197`) — resolution goes through a
   securejoin-style boundary, and a final `Lstat` refuses symlink targets.
7. **The two-key model is enforced, not just documented** (ADR-022):
   fingerprint distinctness is checked in every command that sees both keys.
8. **Unavailable evidence is reported as unavailable, never fabricated** —
   the `scripts/check-rulesets.py` SKIP-loudly contract, generalized. And the
   family is flags-only: no prompts, no TTY detection (there is no terminal
   in the ADR-018-shaped call path — the reasoning already recorded at
   `internal/sshsig/sign.go:70-73` — and the guides' "executed as written"
   property requires deterministic transcripts).

## 3. Ship first: a documentation PR, before any code

The steelman (§8, attack 5) forced an honest re-ordering: two of the
highest-recurrence pain items need no code at all, and a proposal that needs
them to remain unfixed to justify itself would be arguing in bad faith. The
following ships as a guides PR immediately, independent of everything else:

1. **The fetch refspec, documented once as configuration** — add to the
   bootstrap and contributor guides:
   `git config --add remote.origin.fetch 'refs/attestations/*:refs/attestations/*'`
   From then on every `git fetch`/`pull` moves attestation evidence
   automatically, killing the consume half of problem #6 today. **Force
   semantics are decided here as non-force**: attestation refs are
   content-addressed and append-only — `EnvelopeRef` names each ref from
   the envelope bytes' digest (`internal/attest/store.go:46-49`), and
   supersession adds refs rather than moving them (spec §8.1) — so a
   legitimately fetched ref never changes, non-force loses nothing, and a
   remote-side ref mutation surfaces as a visible fetch refusal instead of
   a silent local replacement. This matches the guides' existing
   plain-fetch line (bootstrap-github.md:290); ADR-4 ratifies. (The push
   half stays an explicit command; see §4 on why a push refspec is never
   written.)
2. **The commit-msg trailer hook, committed in-tree** — the hook already
   documented at `docs/reference/trailers.md:159-176` becomes a committed
   script, installed with one line (`core.hooksPath` or the documented
   `chmod`), closing the mechanical half of problems #7/#8.
3. **Path-scoped founding commit** — `bootstrap-github.md:137` currently
   reads `git add -A`; in the guide's empty-dir transcript that is harmless,
   but it is the pattern people copy into directories that already have
   code. Change to `git add .semver-trust .gitmessage` (see §6).
4. **The canonical ordering recipe** (§6) — a short subsection in the
   bootstrap guide stating what must precede the first commit and why, and
   that pre-share rebase-and-resign is the legitimate day-one recovery.
5. **Agent-contract lines** — the `agent.md` drop-in block gains the
   bootstrap prohibition and the un-bootstrapped-repo rule (§6.4), parallel
   to its existing `attest`/`release`/`promote` prohibition.

After this PR lands, **re-rank the thirteen**. The prediction (§8) is that
the surviving majority of pain sits in `enroll`'s territory — registry
formats, namespaces, key distinctness — which is then the honest, measured
justification for the code phases below.

## 4. The command family

### 4.1 Initial commitment: `doctor`, `enroll`, `setup`

Three commands. Two of them write nothing at all or working-tree files only;
one writes repo-local git configuration. Nothing in the initial commitment
touches `~/.ssh` or installs executable code.

#### `semver-trust doctor` — read-only diagnosis

```
semver-trust doctor [--repo .] [--persona maintainer|contributor|agent]
                    [--staged] [--commit REV] [--message FILE|-]
                    [--at RFC3339] [--strict] [--json]
```

Strictly read-only — the command has no write path, which is what makes its
agent mode safe by construction. The wall clock is read once at the process
boundary (ADR-018 shape) as the default `--at` and disclosed in the header.

- **Personas.** Auto-detected for humans (a principal present in
  `attestation_signers` selects the maintainer check-set; otherwise
  contributor), always disclosed in the header
  (`persona: contributor (auto-detected; --persona to override)`). Persona
  is what maps a condition to the right severity: an absent attestation key
  is *correct* for a contributor and FAIL for a maintainer. `--persona
  agent` is never auto-detected — it is a contract, requested explicitly,
  and restricts the run to a side-effect-free subset: no sign-roundtrip
  (could hit a passphrase prompt), no network, no prompts; FAIL means "do
  not commit; report to your operator."
- **Severity and exit.** `PASS`/`WARN`/`FAIL`/`SKIP` per check; exit stays
  binary (0 unless any FAIL — the repo-wide 0/1 convention); `--strict`
  promotes WARN to FAIL for humans who want it. SKIP never affects the exit
  code but is always printed (principle 8).
- **Output contract** (a steelman consequence, §8 attack 3): the summary
  line never renders a health verdict — no "all checks passed"; every
  transcript ends with a structural *cannot-check* footer naming what no
  tool can verify (that the key is held only by you; that a reviewer is a
  distinct natural person; live platform enforcement — see the SKIPs).
  Every FAIL carries `would abort at verify: §10 step N …` in the
  verifier's own vocabulary, and a `fix:` line naming the exact next
  command — doctor is the family's discoverability spine. Every run ends by
  printing the filled-in `verify` invocation: doctor is the on-ramp to
  verify, never its replacement, and the accompanying ADR recommends
  **against** wiring doctor into CI (verify is the CI gate).
- **Hardening** (risk register consequences): the repo-relative path fence
  (principle 6) applies to doctor's working-tree reads of policy-named paths
  (DR-1 — a hostile repo's policy must not be able to point doctor's reader
  at `~/.ssh/id_ed25519`); parse errors report line numbers and repo-relative
  paths, never file content bytes; the optional key sign-roundtrip signs
  only a compiled-in constant, never bytes a repository can influence (DR-2
  — otherwise a cloned repo obtains a signing oracle over the enrolled key);
  linked-worktree detection gates the config checks (SU-6 — go-git resolves
  an empty config in linked worktrees, which would otherwise produce false
  FAILs); when `include`/`includeIf` keys are present in git config, every
  config-derived answer carries a disclosed caveat (go-git does not expand
  includes; SU-5).
- **Naming.** `doctor` is retained for legibility (`brew doctor`,
  `flutter doctor`) — the steelman's worry that the name implies a clean
  bill of health is answered by the output contract above; the internal
  package is `internal/preflight`, which names the true relationship to
  verify.

The full check catalog is §5.

#### `semver-trust enroll` — the family's paradigm

```
semver-trust enroll [--repo .] [--email E]
                    [--commit-key PATH.pub] [--attest-key PATH.pub]
                    [--gpg-pubkey FILE|-]        # at least one target
                    [--write] [--dry-run]
```

**Print-by-default.** The default mode emits *only* the byte-exact registry
line(s) on stdout — raw registry bytes, safe for `>>` redirection and
nothing else — with all explanation on stderr:

```
$ semver-trust enroll --commit-key ~/.ssh/semver-trust-commit.pub
alex@example.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI…
```

stderr names the only sanctioned compositions — paste into an enrollment PR,
`>> .semver-trust/allowed_signers`, or `--write` — and explicitly warns
against retyping the line (shell quoting eats `namespaces="git"`; that is
problem #2, and the tool must never print an `echo`/`printf` form anywhere).
The namespace strings come from compiled constants —
`attest.Namespace = "attestation@semver-trust.dev"`
(`internal/attest/attest.go:36-39`) and the `git` namespace constant — so
problem #2 becomes untypeable. The principal defaults from
`git config user.email` via the same resolution `vcs.Tagger` uses
(`internal/vcs/create.go:65-87`), making the problem-#1 invariant (registry
principal equals commit identity) true by construction; `--email` overrides
with a stderr warning.

**`--write`** appends to the working-tree registry file(s) under the full
writer discipline:

1. Repo-relative path fence on the policy-named target (principle 6; EN-1).
2. No parent-directory creation — a missing parent is a refusal with a hint,
   never a `MkdirAll` (EN-6).
3. Refuse if the existing file fails the strict parser ("fix the registry
   first: line N") — the tool never launders a broken registry (EN-4).
4. Build the new content in memory; re-parse the **whole result** with
   `sshsig.ParseAllowedSigners` / `pgp.ParseKeyring`; then temp-file, fsync,
   rename (principle 5; EN-3).
5. Duplicate key ⇒ refusal ("already enrolled as `<principal>`"); same email
   with a different key appends with a WARN (multiple keys per principal are
   legal); a key that would appear in both `allowed_signers` and
   `attestation_signers` ⇒ refusal (ADR-022, principle 7).
6. Self-check the appended line via `sshsig.Resolve` in the target
   namespace (`allowedsigners.go:199-217`) — the enrollment is verified by
   the verifier's own resolver before the human ever commits it.
7. **Mandatory identity disclosure:** every `--write` prints the key
   fingerprint(s) and, for GPG input, the `pgp.Principals()` diff — the tool
   always shows exactly whose authority is being added.
8. Never stages, never commits; prints a suggested *path-scoped* enrollment
   commit command (§6).

**GPG input.** Never shells out to `gpg`, never accepts a bare key ID (that
would require a keyring lookup the tool cannot honestly do). The contract is
instruct-the-user for the gpg interaction, parse-and-validate for the trust
material: the user exports (`gpg --armor --export KEYID > key.asc`, exactly
as `bootstrap-github.md:81` already documents), and `--gpg-pubkey FILE|-`
validates the armored input via the multi-block-aware `pgp.ParseKeyring`
(`internal/pgp/pgp.go:62`), refuses private-key material loudly, and
requires ≥1 new key (a no-op append is a refusal, not a silent success).
stdin is supported for composability — but the documented walkthroughs show
**fetch to a file, inspect, then enroll**; the one-line
`curl … | enroll --gpg-pubkey - --write` idiom is deliberately absent from
every guide (§8, attack 7: "network → trust root in one line" is the
anti-pattern the enrollment ceremony exists to prevent).

#### `semver-trust setup` — this clone's git configuration, and nothing else

```
semver-trust setup [--repo .] [--remote origin]
                   (--signing-key PATH.pub | --gpg-signing-key KEYID)
                   [--force] [--dry-run]
```

Writes **repo-local git configuration only** — never `--global`, never the
working tree, and (a steelman cut) **no hook installation**: a hook is
persistent code executed on every commit, and installing one is the single
genuine capability escalation the original design contained. The committed
hook script plus one printed `core.hooksPath` line (§3) does the same job
without the trust tool writing executable code — and moots the Windows and
hook-manager (husky et al.) interaction problems in the same stroke.

Keys managed: `gpg.format`, `user.signingkey`, `commit.gpgsign`,
`commit.template` (only if `.gitmessage` exists — otherwise a WARN with
"re-run after creating it"), `gpg.ssh.allowedSignersFile` (SSH mode, file
present), and an **append** to `remote.<name>.fetch` of
`refs/attestations/*:refs/attestations/*` (non-force; §3). The push refspec is deliberately
never written: setting `remote.<name>.push` changes what a bare `git push`
means — a config landmine worse than the disease. Publishing evidence stays
one printed command, which `release` and `attest --store` output already
names.

**The config-write mechanism is constrained by a verified finding** (§7,
headline 1): go-git v5.19.1's `SetConfig` is a lockless, truncate-in-place,
whole-file rewrite (`storage/filesystem/config.go:28-47` →
`dotgit.go:182-184`, `O_CREATE|O_TRUNC` on `.git/config` directly) that
destroys comments (`plumbing/format/config/decoder.go:22-37` never models
them) and corrupts `pushurl` remotes on round-trip. An interrupt mid-write
leaves an empty `.git/config` — to the user, a destroyed repository. Raw
`SetConfig` is therefore **forbidden** for this family. The recommendation:

> **Environment tooling shells out to `git config`; verification stays
> pure go-git.** The go-git-only convention exists for verification
> determinism — reads from trees, injectable clocks, no environment
> dependence. Setup is the opposite kind of code: its correctness *is*
> fidelity to the user's actual git — locking (`config.lock`), include
> semantics, worktree config routing, `GIT_DIR` handling — all of which the
> git binary gets right for free and go-git gets wrong today. A scoped ADR
> exception (§10, ADR-7) draws this line explicitly.

(The fallback, if the project rejects any shell-out: a git-compatible
lock+rename textual patcher that edits only the keys setup owns and never
re-marshals sections it does not — the risk register's SU-1..4 mitigations.
More code, same guarantees; the recommendation stands on simplicity.)

Remaining semantics, all risk-register consequences:

- **All-or-nothing conflict handling:** the full change-set is computed
  first; any key already set to a different value fails the run listing
  every conflict, writing nothing. `--force` overwrites, printing
  `key: old → new` for every change — and **never applies to
  `user.signingkey`** (SU-11: silently swapping a company-mandated signing
  identity is the one overwrite no convenience flag should perform; that
  conflict is always a refusal with the manual command printed). Error
  messages never suggest `--force` for identity or signing-key conflicts.
- **Idempotent re-runs:** keys already at target values report
  `ok (already set)`; the refspec idempotency check compares *parsed*
  refspecs (src/dst/force normalized), not strings (SU-9).
- **Remote selection is visible:** `--remote` defaults to `origin`, and the
  chosen remote plus its URL are echoed (SU-8 — fork workflows have
  `origin` = fork, `upstream` = canonical; the echo plus a doctor WARN when
  multiple remotes exist keeps the wrong-remote failure visible rather than
  silent).
- **Environment honesty:** the resolved repository root and gitdir are the
  first output line of every run, dry-run included (IN-1/SU-7 — `--repo`
  defaults to `.` and repository detection walks up; the echo is the audit
  trail). Linked worktrees, bare repositories, and `GIT_DIR`/`GIT_CONFIG*`
  environments are detected and refused with the manual commands printed
  (SU-6/7) — if shelling out to `git config`, the worktree case can instead
  be supported honestly, with a disclosure that shared config affects all
  worktrees. Include-based configs (SU-5): when `include`/`includeIf` is
  present and a managed key appears unset, setup downgrades to WARN and
  prints the manual commands instead of writing over a deliberate corporate
  config.
- **Reversal receipt:** every run ends by printing the exact reversal
  commands (`git config --unset …`, one per written key) — an undo
  instruction costs ten lines of output and removes the need for an undo
  *mode* with its own clobber risks (SU-12).
- **Refuses to run as root** (CC-4), and `--dry-run` prints the plan as
  `git config` commands — the dry-run output *is* the manual fallback,
  byte-for-byte.
- **ADR-022 cross-check:** if the offered signing key's public half appears
  in `attestation_signers`, refuse ("this key is enrolled as an attestation
  key; commit and attestation keys must be distinct").

### 4.2 Deferred, with recorded designs and un-defer preconditions

**`semver-trust keys generate` — deferred** until the signing stack supports
passphrase-protected or agent-held keys. `sshsig.LoadSigner` rejects
encrypted keys by design (`internal/sshsig/sign.go:70-85`), so today the
tool could only mint passphrase-less accountability keys as a silent
default — where `ssh-keygen` at least makes choosing an empty passphrase an
interactive act (§8, attack 6). The recorded design, whose mitigations are
preconditions for un-deferral: in-process ed25519 generation (no shell-out);
default filenames `~/.ssh/semver-trust-commit`/`-attest` — deliberately
outside ssh's `id_*` default-lookup globs so no ssh client or `ssh-add`
glob picks them up (KG-1/KG-8); `O_EXCL` creation with the final mode passed
at open, never create-then-chmod (KG-3/KG-4 — `O_EXCL` also refuses
symlinks, dangling included); refuse-if-exists across all four target files
with **no `--force` flag at all** (deleting keys is `rm`, a deliberate human
act); no parent-directory creation (refuse if `~/.ssh` is absent, with a
`mkdir -m 700` hint); all-or-nothing with cleanup that removes only files
this run's process actually created (KG-2/KG-6); resolved absolute paths
echoed; output states "this key signs commits — do not `ssh-add` it for
server authentication" and prints both fingerprints, the ADR-022
distinctness line, and the byte-exact future enrollment lines via `enroll`'s
formatter. Until then, the guides' two `ssh-keygen` invocations remain — they
are the *lowest*-pain steps in the catalog.

**`semver-trust init` — deferred, likely permanently.** The steelman's one
structural hit (§8, attack 1): the founding commit is the maximum-stakes,
minimum-frequency moment, and `init` is the one command whose generated
material is not forced through human eyes — `git add -A && git commit` over
four files the maintainer plausibly never read is checkbox compliance with
extra steps, at the exact commit ADR-028 makes govern everything downstream.
And `init` decomposes completely: the policy heredoc
(`bootstrap-github.md:104-127`) is copy-paste-stable and is the one artifact
a founding maintainer *should* read line by line; the format-sensitive
registry lines are `enroll`'s job; meta-path coverage and the
adoption-boundary ordering trap are doctor checks; the config block is
`setup`. The founding flow without `init` is §4.3 below. If `init` is ever
revived, the recorded preconditions: print-by-default mandatory (working-tree
writes opt-in), refuse-if-exists for `.gitmessage` independently of
`.semver-trust/` (IN-2), tmp-dir-then-rename all-or-nothing scaffold (IN-3),
and an explicit `--repo` required whenever the detected root differs from
the working directory (IN-1). It would still never accept an
`adoption_boundary` flag — ADR-026's reasoning extends to generation time:
the single most consequential admission in the scheme stays a one-line
hand-edit to a file under review.

**Phase-3 horizon (remote-aware), unchanged from the original design and
deferred with triggers:** `sync` (push/fetch wrapper carrying the
attestation refspec — the first remote/auth surface in the codebase),
`doctor --online`, `reproduce <tag>` (fetch refs, extract the recorded
`predicate.timestamp`, run verify under the injected clock — mechanizing
problems #10/#11; additionally gated on conformance vectors covering
injected-clock verification, since what a reproduction run *claims* is a
verification-semantics statement), and `merge` (a `merge-pr.sh` port whose
self-check becomes the real single-commit simulation instead of a `%G?`
grep). Highest effort and risk of the family; nothing in the initial
commitment depends on it.

### 4.3 Persona walkthroughs (after)

**Greenfield maintainer** — `bootstrap-github.md` §1–3's eighteen commands
and two `printf`/`cut` incantations become:

```sh
git init -b main widget && cd widget
git config user.name "Alex Doe"
git config user.email alex@example.com          # git's own identity: retained manual
ssh-keygen -t ed25519 -f ~/.ssh/semver-trust-commit -C 'alex@example.com commit signing'
ssh-keygen -t ed25519 -f ~/.ssh/semver-trust-attest -C 'semver-trust attestation signing'
mkdir .semver-trust
cat > .semver-trust/policy.toml <<'EOF'        # the one artifact to read line by line
…                                              # (the guide's §3 heredoc, unchanged)
EOF
semver-trust enroll --commit-key ~/.ssh/semver-trust-commit.pub --write
semver-trust enroll --attest-key ~/.ssh/semver-trust-attest.pub --write
printf 'Provenance: human\n' > .gitmessage
semver-trust setup --signing-key ~/.ssh/semver-trust-commit.pub   # after the files it wires up
git add .semver-trust .gitmessage              # path-scoped: the pure adoption commit
git commit -m "chore: adopt semver-trust" -m "Provenance: human"
semver-trust doctor                            # prints the first verify invocation
```

(The ordering is itself §6's recipe: `setup` runs after the policy,
registries, and `.gitmessage` exist — so `commit.template` and
`gpg.ssh.allowedSignersFile` bind to real files — and before the first
commit, so that commit is signed and trailered.)

Problems #1 and #2 become untypeable; #3 is now checked twice (enroll's
cross-registry refusal, doctor's fingerprint check); #6's consume half is
configuration; #9's meta-coverage is a doctor check. The policy remains
hand-committed by design. §4 onward of the guide — work, verify, the
release ceremony — is unchanged.

**Contributor** — `contributor.md`'s one-time setup becomes:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/semver-trust-commit -C 'you@example.com commit signing'
semver-trust setup --signing-key ~/.ssh/semver-trust-commit.pub
semver-trust enroll --commit-key ~/.ssh/semver-trust-commit.pub   # → the one PR line
semver-trust doctor          # expected FAIL "not enrolled — until your PR merges"
```

**Legacy adopter** — bootstrap as above on the existing history, then the
archaeology loop driven by `verify` aborts with doctor-vocabulary hints:
unknown GPG signer → fetch the key **to a file**, inspect it, then
`semver-trust enroll --gpg-pubkey dev.asc --write` (principals diff printed);
unsigned historical commit → "no key can fix this; this is what the adoption
boundary is for — add `adoption_boundary = "<rev>"` to policy.toml by hand."
Doctor confirms the boundary resolves, matches the bootstrap descriptor when
one is supplied, and that the active policy's meta-paths cover the trust
material.

**Agent** — `semver-trust doctor --persona agent` at session start;
`--persona agent --message MSGFILE` before committing; `--persona agent
--commit HEAD` after. The only family command an agent is sanctioned to run
(§3 item 5, §10 ADR-6).

## 5. The doctor check catalog

Notation: persona M/C/A; severity is the worst outcome; every FAIL names the
verify abort it preempts. Primitives cited once here, reused throughout:
`Resolve` (`allowedsigners.go:203`, sentinels `ErrUnknownSigner`/
`ErrRevokedSigner` :191-197), `ParseAllowedSigners` (:44),
`pgp.ParseKeyring`/`Principals` (`pgp.go:62`/`:186`), `policy.Parse`,
`trust.Classify` (`classify.go:93`), the trailer parser, `readTreeFile`
(`tree.go:35`), `attest.GitRefStore.List` (`store.go:88`), `vcs.Tagger`
(`create.go:70`).

**config/** —
`identity` (M,C: user.name/email set, via Tagger's resolution; FAIL);
`signing-enabled` (M,C,A: gpg.format/user.signingkey/commit.gpgsign; FAIL —
for A this is agent-contract rule "never disable signing");
`commit-template` (C: template exists **and its content parses as a trailer
block** when fed through the trailer parser — a template that would not
classify is a lie waiting to happen; WARN, since `-m` bypasses it anyway);
`allowed-signers-file` (C: `gpg.ssh.allowedSignersFile` points at the repo
registry, enabling local `git log --format=%G?`; WARN);
`hook` (C: trailer hook reachable via effective `core.hooksPath`; WARN).
All config-derived checks carry the includes-not-expanded caveat when
`include`/`includeIf` keys are present, and are gated on worktree detection.

**keys/** —
`signing-key-loads` (M,C: the configured public key parses; fingerprint
printed; FAIL);
`configured-vs-enrolled` (M,C: the `user.signingkey` fingerprint matches the
`allowed_signers` entry for `user.email` — the two-keys-same-email confusion
check, KG-9; FAIL for M, WARN for C pre-enrollment);
`attestation-distinct` (M: commit and attestation key fingerprints differ —
**checked by nothing anywhere today**; FAIL, ADR-022);
`attestation-family` (M: attestation entries are SSH keys, enforced
structurally by the parser; FAIL);
`sign-roundtrip` (M: load + sign **a compiled-in constant** + verify; SKIP
when passphrase-protected or agent-held — never a prompt, never
repo-influenced bytes).

**registry/** —
`parse` (M,C: both registries parse, from **HEAD's tree and the working
tree**; drift between them is a WARN — "verify reads the range tip's tree,
not your checkout"; FAIL preempting §10 step 3);
`self-enrolled` (M,C: `Resolve(key, signers, "git", at)`; on
`ErrUnknownSigner`, print the ready-to-paste line via `enroll`'s formatter;
on `ErrRevokedSigner`, re-Resolve under `attest.Namespace` and, if that
succeeds, say precisely: "your line carries the attestation namespace;
commit signing needs `namespaces=\"git\"`" — problem #2 diagnosed, not
documented; FAIL, with the expected-until-your-PR-merges framing for C);
`principal-matches-email` (M FAIL, C WARN: the resolved principal equals
`user.email` — checkable before any signature exists);
`gpg-keyring` (M: declared keyring parses from the tree; zero entities is a
FAIL — declared-but-empty fails closed);
`bot-accounts` (M: each `identity.agent.bot_accounts` entry intersects the
enrolled principals; WARN — an unmatched bot account means platform merges
will resolve unknown-signer or classify human).

**policy/** —
`parse` (M,C,A: strict parse + digest, worktree and HEAD tree, drift WARN;
FAIL preempting §10 step 1);
`meta-coverage` (M: meta-paths cover the policy itself, both registries, the
keyring, and CI workflow paths; WARN);
`adoption-boundary` (M: the declared boundary resolves to an existing
object; when a bootstrap descriptor is supplied (`--bootstrap-descriptor` —
the out-of-band chain authority under draft v0.10, spec §5.2/§5.4; post-#76
it governs the whole recurring chain, not only the genesis boundary), the
in-policy value matches its pin — mismatch is FAIL, no descriptor is a loud
SKIP ("descriptor match not checkable"); and the commit that introduced or
last changed `adoption_boundary` individually passes the §5.4 meta gate
under the **active** policy — the ordering trap of problem #9 in its
correct form. The boundary commit's own tree is deliberately *not*
consulted: in legacy adoption it predates the scheme and need carry no
policy at all. Never suggests a flag).

**chain/** — the accepted-predecessor tier, live once a `release/v0.2` chain
head exists for the component (post-#76):
`chain-head` (M: for `(repo, component)`, the accepted chain head is unique and
its complete chain verifies genesis→head — a read-only projection of
`chain.AcceptedChainHead`; a fork (2+ heads), a cycle, a broken `prior_state`
hash-link, an unverifiable member signature, or a moved/recreated head tag is a
FAIL naming the §7.5/ADR-027 break it preempts at release/verify time; no chain
head yet is a SKIP, "genesis — no accepted predecessor". Never a flag).

**simulate/** — the verify-one-artifact-in-isolation tier, all pure
functions over local state:
`classify` (M,C,A: classify `--message FILE|-` or `--commit REV` through
`trust.Classify` with the policy's `TrailersRequired`; the killer detection
is a message that *contains* `Provenance:` but whose trailer block is not
the final paragraph — it parses as absent and floors silently, problem #8's
exact mechanism; FAIL under a mandating policy, and for A the honest
framing: "authorship=agent level=T0 (own) — expected; one signed human
review lifts to T2");
`commit` (M,C,A: the full single-commit §10-step-3 path — signature,
key-family, registry resolution, trailer classification — on any rev; this
is what replaces `merge-pr.sh`'s grep, problem #13);
`meta-touch` (`--staged`: the staged paths against the policy's meta globs;
WARN for humans — "this commit must individually reach the meta
required-level"; **FAIL for agents** — "you are about to touch trust
material; stop and surface to your operator");
`staged-purity` (M,C: staged changes mix meta-paths and non-meta paths;
WARN — "adoption and enrollment commits should carry trust material alone";
§6);
`enrollment-line` (M,C: dry-run a candidate registry line from stdin
through the strict parser and Resolve, before the PR exists).

**history/** —
`pre-adoption` (M, in a repo with commits but no `.semver-trust` at HEAD:
triage existing history — unsigned commits, missing trailers — and state
the recovery honestly: "history not yet shared: rebase-and-resign now is
clean; after sharing, this becomes an adoption boundary"; §6).

**trust/** —
`agent-provenance` (M: trust-material commits in history carrying
`Provenance: agent` — defense-in-depth for the agent contract, CC-5; WARN).

**remote/platform/** — the honest-unavailability tier:
`fetch-refspec` (M,C: the attestation refspec present on the chosen remote,
parsed-refspec comparison; WARN with the exact `git config --add` fix);
`attestation-refs-local` (M: release tags without local attestation refs
via `GitRefStore.List`; WARN; whether the *remote* has them is SKIP
offline);
`rulesets` (M: committed ruleset JSON present and parseable; the live
comparison is **always SKIP** with a pointer to
`scripts/check-rulesets.py` — deliberately not reimplemented);
`release-baseline` (M: INFO only — latest tag, the exact next `--from`, and
the recorded `predicate.timestamp` reproduction incantation for the latest
release; problems #10/#11 as printed discipline).

## 6. Bootstrap ordering and commit purity

A question raised during review: when bootstrapping is comingled with other
changes, must the semver-trust commit come first? The intuitive answer —
"trust material must be commit #1" — is wrong under the scheme's semantics,
and the correction is worth a section because the *actual* invariants are
different and sharper.

**The correction.** Verification reads trust material from the **tip** of
the range being verified — the registries are read "from the tree at the
*tip* of the range" (trust-material.md:121), and the policy from TO's tree
(§10 step 1; `internal/verify/tree.go:32-35`). A repository whose first
commits are code and whose third commit adds `.semver-trust/` verifies
cleanly at any tip that contains the trust material, because the tip's
registries retroactively cover the earlier signatures.
Trust-material-first is **not** required for verifiability. What is
required, ranked by severity:

1. **Signing configured before the first commit.** An unsigned commit is an
   abort — unverifiable is never T0 — and it is unrecoverable except by
   history rewrite or an adoption boundary. The realistic comingle is
   exactly this: a few "scaffold" commits before bootstrap, unsigned
   *because signing configuration is itself part of the bootstrap*. That
   recreates on day one the adoption-boundary problem greenfield status is
   celebrated for avoiding (bootstrap-github.md:10-14; AGENTS.md calls the
   unbroken history "a project deliverable in itself"). The honest, missing
   guidance: **before the repository is shared, rebase-and-resign is a
   legitimate, clean recovery** — history rewriting is only forbidden on
   shared/protected branches. The docs PR (§3) adds this sentence; the
   `history/pre-adoption` doctor check (§5) states it case-by-case.
2. **Trailers from the first commit.** Untrailered commits under
   `[trailers] require = true` classify ambiguous and floor the scope at T0
   (`classify.go:121-132`). Recoverable by review-lift, but pointless
   ceremony when one line of ordering advice prevents it.
3. **Adoption-commit purity.** A commit that mixes `.semver-trust/**` with
   ordinary code is semantically valid — it is meta-gated and a signed,
   trailered, human-authored commit meets a T2 requirement — but it buries
   the scheme's most consequential content in noise. The founding and
   enrollment commits are the ones outside reviewers will re-derive and
   audit; they should be readable as pure accountability acts. Purity is a
   convention, not a rule, so the tooling posture is: doctor
   `staged-purity` WARNs humans; every generator prints **path-scoped**
   commit suggestions (`git add .semver-trust .gitmessage`, never `-A`);
   and the guide's own `git add -A` (bootstrap-github.md:137) is fixed in
   the docs PR.
4. **The agent-scaffold variant.** Increasingly the first commits of a new
   repository are agent-authored. An agent-authored commit touching
   meta-paths is T0-authored below any T2 `required_level`, and §5.4
   meta-path violations **abort** — so an agent that "helpfully" bootstraps
   produces an unverifiable repository until a human review lifts it. This
   is handled by contract, not code: the `agent.md` drop-in block gains,
   alongside the bootstrap-command prohibition, the ordering half — *in a
   repository without `.semver-trust/`, do not commit and do not bootstrap;
   surface to your operator* — and doctor's `--persona agent` mode makes
   `meta-touch` a FAIL.

No hard enforcement is proposed anywhere in this section: the tool never
commits (principle 1), so ordering and purity remain human decisions — the
family's job is to make the invariants visible before the mistake exists,
and to stop *agents* (whose contract is checkable) rather than humans.

## 7. Threat model and risk register

The corruption analysis attacked every mutation surface of the original
five-command design. Its verified headline findings reshaped §4; they are
recorded here with the register condensed to the entries that survive in
the initial commitment, plus the honesty ledger. (Full per-command tables
for the deferred `keys generate` and `init` live with their recorded designs
in §4.2 as un-defer preconditions.)

### 7.1 Verified headline findings

1. **go-git v5.19.1 config writing is unsafe for this purpose** — verified
   in the vendored module source, not speculated. `Repository.SetConfig` is
   a lockless truncate-in-place whole-file rewrite
   (`storage/filesystem/config.go:28-47`; `dotgit.go:182-184` opens
   `.git/config` with `O_CREATE|O_TRUNC`), destroys comments (the decoder,
   `plumbing/format/config/decoder.go:22-37`, never models them), ignores
   git's `config.lock`, and corrupts `pushurl` remotes on round-trip
   (`pushurl` values are folded into `URLs` on unmarshal and re-emitted as
   `url =` lines). Consequences: SIGINT mid-write leaves an empty
   `.git/config`; concurrent IDE `git config` writes are silently reverted;
   the contributor fork workflow's push targets break. **Disposition:** raw
   `SetConfig` forbidden; setup shells out to `git config` (or implements
   git's own lock+rename protocol with targeted textual patching) — §4.1.
2. **Policy-named paths are a traversal surface the moment they touch the
   filesystem.** The policy performs no path validation on
   `allowed_signers`/`gpg_keyring`/`attestation_signers`
   (`internal/policy/policy.go:165-190`); verification is safe today only
   because those paths are resolved inside git trees
   (`tree.go:32-35`), which cannot escape the repository. A command that
   reads or writes them in the working tree inherits none of that safety: a
   hostile cloned repository can declare
   `allowed_signers = "../../.ssh/authorized_keys"` (or an in-repo symlink
   escaping the tree) and turn `enroll --write` into an append of
   attacker-shaped key material to `$HOME` — an allowed-signers line is
   close enough to an `authorized_keys` line for this to be an escalation
   path, and even a benign append corrupts the target. **Disposition:**
   principle 6, applied to every read and write of a policy-named path in
   every new command; prior art `attest.validSubject`
   (`store.go:184-197`).
3. **Linked worktrees silently break the naive implementation.** The
   codebase opens repositories without commondir mapping
   (`PlainOpenWithOptions(…, DetectDotGit: true)` — `tree.go:19-21`,
   `create.go:75`); in a linked worktree go-git then resolves an **empty
   config**, so a naive doctor reports everything unconfigured and a naive
   setup writes a config file git never reads — setup "succeeds," signing
   never activates, and the user's next commit is unsigned: precisely the
   failure class the family exists to eliminate. **Disposition:** worktree
   detection gates doctor's config checks; setup refuses or supports
   worktrees explicitly (free if shelling out to `git config`) — §4.1.
4. **A sign-roundtrip check is a signing oracle unless it signs a
   constant.** Any repo-influenced bytes signed by the user's enrolled key
   hand a hostile repository a valid SSHSIG over chosen content.
   **Disposition:** the roundtrip signs a compiled-in constant, and is
   SKIPped for passphrase/agent-held keys — §5.
5. **Include-blindness.** go-git does not expand `include.path`/`includeIf`
   at all, so config reads miss deliberate (often corporate) configuration;
   writing "missing" keys over an include-based setup silently defeats it.
   **Disposition:** include detection ⇒ WARN + print-manual-commands
   posture in setup; disclosed caveat in doctor — §4.1, §5.
6. **Wrong-repo resolution.** `--repo .` plus walk-up detection can resolve
   to an unintended repository (a parent project; `$HOME` itself under
   dotfile managers). **Disposition:** every command echoes the resolved
   root as its first output line, dry-run included.

### 7.2 Condensed register (initial commitment)

| ID | Surface | Scenario | Mitigation (all adopted in §4) |
|---|---|---|---|
| SU-1/2 | `.git/config` | truncation on interrupt; lost-update vs concurrent writers | git's lock+rename protocol via the git binary; never raw SetConfig |
| SU-3/4 | `.git/config` | comment destruction; `pushurl`/exotic-remote corruption | never round-trip unowned sections; targeted single-key writes |
| SU-5 | config reads | include-blindness → overriding corporate config | detect includes ⇒ WARN + manual commands; disclosed caveat |
| SU-6/7 | worktrees, bare, env | writes git never reads; env/user disagreement | detect; refuse-or-disclose; echo resolved gitdir |
| SU-8/9 | refspec | wrong remote; duplicate under variants | `--remote` echoed with URL; parsed-refspec idempotency |
| SU-11/12 | `--force`; no undo | clobbering deliberate identity config; unrevertable setup | old→new printed; `user.signingkey` never forced; reversal receipt |
| EN-1 | policy paths | hostile repo → filesystem traversal → `authorized_keys` append | principle 6: reject-don't-sanitize, securejoin, Lstat-refuse symlinks |
| EN-3/4 | registry writes | torn append → registry unparseable → verify fails closed for everyone; CRLF/newline joins | in-memory build → strict re-parse → temp+fsync+rename; refuse pre-broken files |
| EN-5 | enroll stdout | pasted line shell-mangled → namespace silently absent | stdout = raw bytes only; sanctioned compositions on stderr; no echo/printf forms ever |
| EN-6 | registry writes | parent-dir creation at attacker-chosen or typo'd paths | no parent-directory creation, anywhere |
| DR-1/2 | doctor reads; roundtrip | content leak via parse errors; signing oracle | repo-relative fence; no content bytes in errors; constant-only signing |
| CC-2/3 | dry-run; TOCTOU | dry-run side effects; check-then-write races | dry-run performs zero mutations; the write itself is the atomic check (O_EXCL, lock) |
| CC-4 | privilege | `sudo` runs → root-owned files in `~`/repo | writers refuse euid 0 |
| CC-5 | agents | agents running generators, manufacturing "human" material | contract line (§3.5); doctor `trust/agent-provenance`; optionally an env tripwire — recorded as defense-in-depth, documented bypassable |

### 7.3 The honesty ledger

The register's most important output is the distinction the proposal must
state plainly:

- **Risks the tool would CREATE** (each acceptable only via its named
  mitigation): config truncation and lost-updates (SU-1/2), comment and
  remote corruption (SU-3/4), include-override (SU-5), worktree misrouting
  (SU-6), filesystem traversal via policy paths (EN-1/DR-1), torn registry
  writes (EN-3), root-ownership landmines (CC-4), the signing oracle
  (DR-2), agent-run generators (CC-5) — and, in the deferred designs,
  key-clobber and partial keypair writes (KG-1..8) and wrong-repo scaffolds
  (IN-1/3). Automation is not free; this is its price, and each line item
  is why the corresponding §4 rule exists.
- **Preexisting risks the tool improves**: shell-mangled registry lines
  (problem #2 — validation plus raw-bytes stdout), append hygiene
  (problem #4 — strict re-parse), wrong-remote refspecs (the guides
  hard-code `origin` today), refspec duplication, hook-manager conflicts
  (mooted by not installing hooks), two-keys-same-email confusion (a new
  doctor check), key-material-in-memory (identical to `ssh-keygen`). For
  these the family is strictly safer than the `printf`/heredoc flow — which
  is its legitimate selling point, and the only one it needs.

## 8. Steelman and dispositions

A steelman pass was run against the full original design in the genre of
the spec repository's `docs/analysis/2026-07-04-steelman.md`. The counter-thesis, in its strongest form: *this
scheme uniquely prices honesty and human attention, so tooling that removes
attention from the trust path attacks the product's one differentiating
property.* Nine attacks were developed; each is recorded with its
disposition. Two landed structurally.

1. **Accountability erosion** — "enrollment is the accountability
   assertion" (trust-material.md:99-115); does a generator reduce the
   founding commit to `git add -A` over unread files, manufacturing the
   rubber-stamp the spec derides? *Disposition:* the attack **collapses for
   `enroll`** — today's `printf … >>` redirect puts the registry line in
   front of no one, while print-by-default puts the byte-exact line on
   stdout, in front of the human, at the accountability moment; strictly
   more attention than the status quo. The attack **lands for `init`**,
   the one command whose output isn't forced through eyes at the
   maximum-stakes commit. Consequence: `init` deferred/likely dropped
   (§4.2); print-by-default promoted to family invariant (principle 4).
2. **TCB expansion / circularity** — the verifier becomes a mutation engine
   that writes what it later attests. *Disposition:* mostly rebutted — the
   binary already loads private keys and signs (release/attest); the
   sharpest verifier compromise is lying about results, which is invisible,
   whereas root writes land unstaged in the working tree and cannot enter
   history except through a human-signed commit past the meta-path gate:
   the trust boundary is the signed commit, and no command crosses it. Two
   pieces survive: **the hook installer was a genuine capability
   escalation** (persistent code execution installed by the trust tool) —
   cut, replaced by the committed script (§3); and the read/write
   invariant is frozen in an ADR capability table (§10) so the next
   convenience feature must supersede an ADR to widen it.
3. **Doctor as oracle** — a green board read as "secure," displacing the
   guides' read-it-honestly pedagogy; WARN-fatigue; a `--strict` CI
   treadmill. *Disposition:* largely answered by design (FAIL = verify
   abort moved earlier; SKIP-loudly; ends by printing the verify
   invocation), and hardened in the output contract: no health-verdict
   summary, a structural cannot-check footer on every transcript, and an
   ADR recommendation against CI wiring (§4.1). Standing prediction
   recorded: if doctor ships with any "healthy"-shaped summary, green-board
   screenshots will appear in adoption discussions as security claims
   within a release cycle.
4. **Scope and sequencing** — a pre-1.0, conformance-gated project spending
   ~six packages and a quarter more ADRs on supply-side polish while the
   prior steelman's near-fatal gap (consumer demand) stands; and interop
   ADRs (enrollment-line format, minimal-policy defaults) with zero
   conformance vectors are either semantics-before-vectors or premature
   standardization. *Disposition:* conceded in structure — the prior
   steelman's §3.1.3 ("attestation ergonomics are product surface")
   legitimizes the doctor/setup half of the family and says nothing about
   generators; the phase boundary now sits exactly there. P2 is conditional
   on a recorded revisit trigger; the two interop ADR candidates are
   withdrawn from the initial batch (§10). The executable-spec property of
   the guides is preserved by keeping byte-level manual appendices (the
   `--dry-run` output *is* the fallback text).
5. **Wrong layer** — generic git pain has generic homes; the two
   top-recurrence items are documentation fixes. *Disposition:* conceded
   and **accelerated** — the docs PR (§3) ships first precisely so the code
   phases are justified only by the semver-trust-proprietary remainder
   (namespaces, registries, distinctness), which no dotfile manager or
   generic signer can address.
6. **Plaintext accountability keys as silent default** — `keys generate`
   deferred on exactly this ground (§4.2).
7. **The vanishing judgment step** — `curl … | enroll --gpg-pubkey - --write`
   as documented muscle memory. *Disposition:* stdin kept (composability);
   the one-liner removed from every walkthrough; the `Principals()` diff
   made mandatory on every write (§4.1).
8. **Agents socialized to a binary with write modes.** *Disposition:*
   capability was never the barrier (an agent can `echo >>` today);
   contract moves with capability — the drop-in prohibition ships in the
   docs PR, `doctor --persona agent` is ADR-named as the single sanctioned
   command, and doctor gains the `trust/agent-provenance` check.
9. **Accumulated smaller** — GPG generation asymmetry (accepted; ADR states
   *generation asymmetry accepted, diagnosis symmetry required* — the
   catalog delivers the latter); `--force` as identity foot-gun (never
   applies to `user.signingkey`); go-git config writing (settled by the
   register, §7.1); Windows hook assumptions (mooted by the hook cut);
   persona auto-detection vs flags-only (kept as a disclosed default; the
   flag remains the contract).

**Verdict table** (what survived):

| Artifact | Verdict |
|---|---|
| Docs PR (refspec, hook, path-scoped add, ordering, agent lines) | Accelerated ahead of all code |
| P0 seam + P1 `doctor` | Intact, with the amended output contract |
| `enroll` | Intact — the family's paradigm |
| `setup` | Amended: no hook install; git-binary config writes; `--force` restrictions |
| `keys generate` | Deferred on the passphrase trigger |
| `init` | Deferred, likely dropped; decomposes into §4.3's flow |
| Interop ADRs (line format, policy defaults) | Withdrawn until vectors exist |
| Capability-table ADR | Strengthened: verify/doctor write-free, forever |

## 9. Phasing

- **Now — the docs PR** (§3). No code. Then re-rank the thirteen.
- **P0 — seam extraction** (refactor only, no behavior change): export a
  `verify.LoadTrustMaterial` wrapper over the unexported resolvers
  (`internal/verify/verify.go` — `resolveHumanSigners`,
  `resolvePGPKeyring`, `buildAttestationVerifier`), and carve the
  single-commit step-3 path into a callable function. Existing tests are
  the safety net.
- **P1 — `doctor`** (`internal/preflight/` + `cmd/semver-trust/doctor.go`)
  plus the ~30-line enrollment-line formatter in `internal/sshsig`
  (`ssh.MarshalAuthorizedKey` is imported but unused today) — the only
  net-new primitive P1 needs. Drift guard: a test per FAIL check asserting
  it wraps the same sentinel error verify uses. P1 adds only the doctor
  invocation examples to agent.md and the guides — the prohibition and
  ordering lines already shipped with the docs PR (§3).
- **P2 — generators, conditional.** Gated on a recorded revisit trigger:
  external adopters reporting bootstrap-failure classes that doctor
  diagnoses but cannot fix, or a second implementation appearing. Order:
  `enroll` (its formatter already exists; its territory tops the
  re-ranked list), then `setup`. Discipline: `--dry-run` everywhere,
  refuse-don't-overwrite, and **every write ends by executing the matching
  doctor check on its own output** — doctor is the generators' acceptance
  oracle.
- **Deferred:** `keys generate` (passphrase-support trigger), `init`
  (§4.2), and the P3 remote horizon (`sync`, `doctor --online`,
  `reproduce` — additionally conformance-gated — and `merge`).

## 10. ADR candidates (spec repository)

Initial batch:

1. **The bootstrap family and the generation/accountability line** — the
   tool writes working-tree trust material and repo-local configuration but
   never stages, commits, or installs executable code; print-by-default is
   the family invariant; enroll's stdout is raw registry bytes. Deferred
   commands (`keys generate`, `init`) and their revisit triggers are
   recorded here.
2. **Two-key distinctness is tool-enforced** — a tool-enforced check and
   convention (doctor, enroll, setup; structural once generation exists),
   phrased so as not to widen ADR-022's normative scope: whether the spec
   itself tightens the two-key model is a separate, explicit decision.
3. **The writer contract** — principle 5 (atomic protocol, dry-run purity,
   interrupted-run guarantees) and principle 6 (the repo-relative fence for
   policy-named paths); proposed here, and made normative by this ADR for
   any command, present or future, that writes.
4. **Fetch refspec yes, push refspec never** — the asymmetry and its
   rationale (a written push refspec changes what bare `git push` means).
5. **ADR-026 extension** — no adoption-boundary affordance on any
   generator, ever; the boundary remains a hand-edit to a reviewed file.
6. **The capability table** — which command may write which class of path
   (`enroll` → policy-named registry files; `setup` → an enumerated set of
   `.git/config` keys; everything else → nothing), with `verify` and
   `doctor` write-free permanently, and the scoped diagnostic exception
   letting doctor *read* git config as evidence. `doctor --persona agent`
   is named the single agent-sanctioned family command. Widening any cell
   requires superseding this ADR.
7. **Environment tooling uses the git binary** — the scoped exception to
   the go-git-only convention, with the line drawn in §4.1: verification =
   go-git (deterministic, tree-only, injectable clock); environment
   mutation and environment diagnosis = the user's git (locking, includes,
   worktrees, `GIT_DIR`). Includes the verified go-git v5.19.1 findings as
   the evidentiary record.

Withdrawn from the initial batch (steelman attack 4): the canonical
enrollment-line interop format and the minimal-policy defaults. Both are
cross-implementation surfaces that should not be standardized before the
spec repository carries conformance vectors for them (the line grammar is a
cheap vector to add, at which point the format ADR revives). Until then
they are implementation-local conventions.

## 11. Open items requiring implementer verification

1. Restate as settled: go-git v5.19.1 `SetConfig` comment loss, missing
   locking, and `pushurl` corruption (§7.1) — if the pure-Go fallback is
   ever pursued, a probe test round-tripping a commented config with
   `pushurl` must gate it.
2. `filepath-securejoin` (already an indirect dependency) — confirm its API
   provides the exact reject/`Lstat` semantics principle 6 needs, or write
   the per-component walk.
3. Worktree config routing — decide refuse vs `EnableDotGitCommonDir` (with
   disclosure) for any pure-go-git path; moot where the git binary is used.
4. Refspec force semantics for `refs/attestations/*` — **resolved in this
   analysis as non-force** (§3, with the content-addressed/append-only
   rationale). Remaining work: ratify in ADR-4 and align any guide or CI
   text that still carries a `+` on this refspec.
5. The agent-environment tripwire (CC-5) — whether generators additionally
   refuse under detected agent environments, which markers are reliable,
   and the override flag's name. Defense-in-depth only; the contract and
   the human enrolling commit remain the real controls.
6. `ssh.MarshalPrivateKey` availability in the vendored `x/crypto` — moot
   until `keys generate` un-defers; verify before building it.

---

## Appendix A — reuse map

| Capability | Status | Location |
|---|---|---|
| Policy parse (strict, digest) / marshal (round-trip) | reuse | `internal/policy/parse.go:111`, `marshal.go:11-15` |
| Registry parsers (line-numbered errors) | reuse | `internal/sshsig/allowedsigners.go:44`; `internal/pgp/pgp.go:62` |
| Enrollment self-check / principal listing | reuse | `allowedsigners.go:191-217` (`Resolve`, sentinels); `pgp.go:186` |
| Signing / key loading (clear passphrase error) | reuse | `internal/sshsig/sign.go:26,:70-85` |
| Git identity resolution | reuse | `internal/vcs/create.go:65-87` (`Tagger`) |
| Tree-only file reads | reuse | `internal/verify/tree.go:32-55` |
| Attestation ref store/list | reuse | `internal/attest/store.go:54,:88` |
| Namespace constants | reuse | `internal/attest/attest.go:36-39` |
| Path-constraint prior art | pattern | `internal/attest/store.go:184-197` (`validSubject`) |
| Verify abort taxonomy (doctor's FAIL vocabulary) | reuse via P0 seam | `internal/verify/verify.go` (resolvers :518/:548/:579; aborts) |
| Trailer classification | reuse | `internal/trust/classify.go:93,:121-152` |
| Enrollment-line formatter | net-new (P1, ~30 lines) | `ssh.MarshalAuthorizedKey`, currently unused |
| Registry writers (atomic, validated) | net-new (P2) | `internal/enroll` |
| Git-config writes | net-new (P2) | git binary per ADR-7; `internal/vcs` wrapper |
| In-process keygen; `policy.New()`; remote ops | net-new, deferred | with their deferred commands |

## Appendix B — method note

Produced from five sub-analyses over `semver-trust-go@71aec5a3ec0d`: (i) a
manual-step catalog of all six guides; (ii) a CLI-surface and house-style
map; (iii) an internals inventory of reusable primitives; (iv) a steelman in
the house genre; (v) a corruption/failure-mode register with go-git v5.19.1
source verification. The adversarial passes (iv–v) were run against the
completed design, and their dispositions — two commands deferred, one
slimmed, the docs PR accelerated, the writer contract added — are reflected
throughout rather than appended, with §7–§8 preserving the audit trail.
