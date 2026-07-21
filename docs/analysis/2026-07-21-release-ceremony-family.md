<!-- SPDX-License-Identifier: Apache-2.0 -->
# Release Ceremony Family — Proposal and Adversarial Analysis

- **Date:** 2026-07-21
- **Status:** Proposal; non-normative — nothing here changes the scheme or the
  implementation except through the repositories' issue, ADR, and conformance
  processes.
- **Specification target:** draft v0.10 (the conformance pin recorded in
  `conformance/manifest.json`).
- **Implementation target:** `semver-trust/semver-trust-go@a2fe62d` (`main` after
  the real-main v0.10 transition; the basis for the `file:line` references).
- **Sibling to:** [`2026-07-19-cli-bootstrap-family.md`](2026-07-19-cli-bootstrap-family.md).
  That document catalogs the **setup/enrollment** ceremony and deliberately defers
  the release/remote commands (`reproduce`, `sync`, `merge`) to its P3 horizon
  (§4.2, §9). This document fills that deferred gap for the **release** ceremony,
  reusing the same method and governing principles.

This document asks whether cutting a v0.10 authenticated release is an outlier in
its roughness or a trend, and — finding a trend — proposes a small release-phase
command family to fix it. It was produced the way the bootstrap-family analysis was:
a catalog of every manual step the release runbook prescribes, grounded against the
real `v0.2.1 → v0.3.0` transition (the [transition record](../history/2026-07-20-v0.10-transition.md));
a design that reuses existing production code wherever the ceremony already has a
verifier-side function; and an adversarial pass — a steelman against the proposal and
a failure-mode analysis of the one genuinely new mutation surface (a descriptor
writer). The adversarial pass matters here for the same reason it did there: this
scheme prices human accountability, and any tooling on the trust path must be shown
not to erode it.

All `file:line` references are into this repository at the implementation pin above.

---

## 1. Problem

Cutting `v0.3.0` — a `release/v0.2` genesis that both starts an authenticated chain
and continues the already-published `release/v0.1` line — worked, but every load-bearing
input was hand-assembled and byte- or OID-exact, and every mistake surfaced **late**:
after the descriptor, the signature, or the push already existed, never while the
mistake was being made. That is the same structural property the bootstrap-family
analysis found in the setup phase (its §1), reproduced one phase downstream.

The catalog below ranks the release-ceremony steps by severity, and — following the
bootstrap doc — classifies each by *how* it fails, because the failure classes call for
different fixes. Items 1–2 fail **silently** (nothing local refuses them); items 3–8 are
**hard §5.4/§5.2 aborts** (loud, but opaque without protocol knowledge); items 9–12 are
**ordering (CI-red) or operator-reading** traps. The two silent ones are the worst.

1. **The CI-variable trailing-newline trap.** The descriptor's identity is `sha256`
   over its **exact raw bytes** (`internal/chain/bootstrap.go:89-92`,
   `sha256.Sum256(d.raw)`), and the genesis attestation binds that digest as its
   `policy_state.authority_identity` (`internal/verify/verify.go:551`). CI re-derives
   the digest from the `BOOTSTRAP_DESCRIPTOR` repository variable, materialized with
   `printf '%s'` — no added newline (`.github/workflows/release.yml:160`). But GitHub
   Actions **strips a trailing newline** from a stored variable value, so a descriptor
   file that ends in `\n` binds one digest at release time and a different one in CI:
   `verify --chain-head` then fails red on the public repo. Nothing local catches it —
   the transition was saved only because the operator manually read the variable back
   and compared digests before pushing the tag (the "Operational note" in the
   transition record). A junior engineer would not know to do that.
2. **A `null` `version_predecessor` silently restarts the line.** To *continue* a
   published line, the descriptor's `version_predecessor` must be the predecessor
   binding, not `null`; a `null` mints `v0.1.0` instead of continuing to `v0.3.0`
   (`docs/recurring-release-runbook.md`, "Continuing an already-published line"). Both
   are structurally valid descriptors — the wrong one produces a wrong version with no
   abort at all.

3. **`trust_material` — one git-blob digest per *declared* registry, and the runbook
   example under-counts.** The recipe computes each digest from the committed blob at
   the release commit — `sha256:$(git cat-file blob "$TO":<path> | sha256sum)` — for
   *every* registry the policy declares. The runbook's JSON example lists two entries,
   but the canonical repo declares three (`allowed_signers`, `gpg-keyring.asc`,
   `attestation_signers`); the descriptor map must equal the declared set exactly
   (`internal/policy/transition.go:136-138`, `bootstrap_trust_material_mismatch`). Copy
   the two-entry example into a three-registry repo and verification hard-aborts at §5.4.
4. **`policy_digest` — same recipe, same abort.** Must be the committed-blob `sha256`
   of `policy.toml` at the release commit, `sha256:`-prefixed
   (`internal/policy/transition.go:133-135`, `bootstrap_policy_mismatch`). Any edit to
   the policy after computing the digest, before tagging, silently invalidates it.
5. **`version_predecessor` — two *different* OIDs, hand-copied.** The binding carries
   `ref_oid` (the annotated tag object's OID) and `commit_oid` (the peeled commit) —
   distinct values that must not be swapped (`internal/chain/predecessor.go:140-145`,
   ref-moved / recreated aborts at §5.2/§7.5). The strict decoder rejects a mistyped key
   name (`internal/chain/bootstrap.go:120`, `DisallowUnknownFields`).
6. **Out-of-band placement.** The descriptor must live outside the repository under
   verification; an in-repo path — or a symlink that resolves back in — is refused
   (`internal/chain/bootstrap.go:104-114`, canonicalized through `EvalSymlinks`). Easy to
   trip by dropping the file in the repo root for convenience.
7. **The review / meta-path prerequisite.** An unreviewed range whose commits touch
   meta-paths (`.github/workflows/**`) **hard-aborts** — not demotes —
   (`internal/policy/transition.go:239-256`, `under_level_meta_commit` at §5.4). One
   maintainer review over the whole interval (`--from` the previous clean tag) lifts the
   agent-authored body to T2 (agent authorship + distinct human review) and clears the
   gate. In the transition, this was diagnosed only *after* a failed verify.
8. **Subject binding and `--repository-digest`.** The descriptor's `repository` and
   `component` must match the verified subject (`internal/verify/verify.go:434-444`,
   `bootstrap_subject_mismatch`), and `--repository-digest` must be a stable value reused
   across the chain.

9. **Publish ordering.** Attestation refs must be pushed **before** the tag, and the CI
   variable set **before** the tag, because the tag push is the trigger and the verify
   job reads both at trigger time (`.github/workflows/release.yml:84`, `:157`). Wrong
   order is a red CI run with no way to reorder except re-pushing.
10. **`--verify-time` discipline.** One injected RFC3339 instant, bound into both tag and
    attestation and reused by every reproducer, chosen to predate any signing-key expiry.
    An out-of-window instant fails signature verification; the wall clock breaks
    reproduction.
11. **Verify-at-head reads as `promotion_required`.** Verifying at the head tag computes
    an empty interval and aborts `promotion_required` **by design**
    (`internal/vcs/interval.go:186-188`) — the chain is valid and this *is* the head. An
    operator can misread it as a failure, or miss a genuinely broken chain thinking it is
    this benign case. (CI sidesteps this with `verify --chain-head`.)
12. **Refused flags.** Under a descriptor, `--from`, `--iteration`, and the three
    trust-material overrides are refused (`cmd/semver-trust/release.go:113-115`; the
    key-substitution guard `internal/verify/verify.go:136-149`); `--predicate v0.2` is
    mandatory and requires `--repository-digest` (`release.go:137-143`).

### 1.4 The shape of the problem

The security semantics are **correct** — fail closed, bind exact bytes, refuse
overrides. Every hard abort names a precise §5.4/§5.2 reason string. What is missing is
an **operator surface**: nothing generates the descriptor, nothing diagnoses the range
before you sign, and nothing catches the two silent traps. The same binary that will
later refuse or mis-price these mistakes can surface them at authoring time, with the
same code — the bootstrap-family premise, applied to release.

## 2. Trend, not outlier

The `v0.3.0` roughness was not bad luck; the operator surface is raw everywhere the same
way.

- The **recurring dogfood ceremony** days earlier needed a bespoke `ceremony.sh` /
  `setup-repo.sh` and hit the same descriptor recipe and the same class of gotchas
  (an adoption `boundary` needs `ref_target == oid`; `version_predecessor` must be
  present) — recorded in [`docs/history/2026-07-20-recurring-dogfood.md`](../history/2026-07-20-recurring-dogfood.md).
- **`v0.1.0`**, the flagship release, already carried the verify-time discipline (a
  recorded instant chosen against key expiry).
- The **bootstrap-family analysis** already ranked thirteen error-prone step classes —
  for setup. The release ceremony is the same genre of manual, byte-exact, late-failing
  work, and it sits precisely in the region that analysis deferred (its P3
  `reproduce`/`sync`).

So the trend is structural, and it compounds: every future release and every external
adopter pays the whole cost again. The fix is not to soften the semantics — they are the
product — but to build the missing surface, exactly as the bootstrap doc argued for
setup.

## 3. Governing principles

Inherited from the bootstrap-family analysis (§2), with the emphases the release phase
sharpens:

1. **The tool generates, formats, and validates the descriptor; the human signs the
   release.** No command in this family runs `attest`, `release`, or `promote`, and none
   signs. The descriptor is not the accountability act — the **signature** is — so
   generating it takes nothing away from the human's signed release, exactly as `enroll`
   takes nothing from the human's signed enrollment commit. This maps onto the existing,
   non-delegable signing constraint the transition ceremony already enforces.
2. **Every preflight FAIL is a verify/release abort moved earlier.** A FAIL calls the
   same function verification calls — `AuthenticateBootstrapTree`, `checkPolicyTransition`,
   the interval/meta-path gate — and names the §5.4/§5.2 reason string it preempts, plus a
   `fix:` line with the exact next command. Checks that are not abort mirrors cap at WARN.
   Guarded by the bootstrap doc's invariant: each FAIL mirror carries a regression test
   asserting it wraps the same sentinel verify uses.
3. **Fail-closed generation.** A generated descriptor is re-parsed by
   `LoadBootstrapDescriptor` and re-authenticated by `AuthenticateBootstrapTree` — and,
   for the roles the standalone path skips, run through the full transition — before it is
   ever written or trusted. The tool never emits a descriptor it would itself reject.
4. **Tree, never worktree.** Every digest in a descriptor is derived from a git tree
   (`internal/verify/metapolicy.go:115-122`, `treeFileDigest`). A generator that hashed
   the working tree would bake an uncommitted edit into the descriptor and produce one
   that authenticates locally but not at the tag's tree. All reads go through the tree.
5. **Canonical bytes by default.** The generator emits a canonical, no-trailing-newline
   descriptor, so the CI-variable round-trip is exact by construction (§6). Where identity
   itself can be made canonical, that is raised as an ADR (§6), not assumed.
6. **The writer contract** (bootstrap doc principle 5–6): the one new write surface — a
   descriptor file — inherits the repo-relative path fence, atomic temp-then-rename, and
   dry-run purity, and is refused inside the repo by the same `LoadBootstrapDescriptor`
   guard that protects verification.
7. **Honest unavailability.** A check that cannot be run offline (does the *remote* carry
   the attestation refs? is the live ruleset enforced?) is a loud SKIP, never a silent
   pass — the `check-rulesets.py` contract, generalized.

## 4. Ship first: documentation fixes, before any code

Following the bootstrap doc's §3, the pain items that need no code ship first, as a
guides PR, so the code phases are justified only by the remainder:

1. **Fix the runbook's `trust_material` example** to show one digest per *declared*
   registry, with an explicit note that the map must equal the policy's declared set
   exactly — the three-vs-two trap of §1.
2. **Promote the round-trip check to a named pre-publish gate.** The no-trailing-newline
   requirement and the `sha256(read-back variable) == Digest()` equivalence check live
   today only in the transition record's Operational note. Move them into the runbook as a
   required step before the tag push.
3. **Make the `null`-vs-binding predecessor decision loud** in the runbook — a `null`
   restarts the line at `v0.1.0`; continuing requires the binding.
4. **Keep the verify-at-head note** (`promotion_required` at the head is success, not
   failure) and add the "verify from a later commit to walk the whole chain" corollary.

After this PR, re-rank the catalog; the prediction (as in the bootstrap doc) is that the
surviving majority sits in descriptor authoring — the code phase below.

## 5. The command family

Three commands plus one convenience. None signs; the writer touches only a descriptor
file outside the repo.

### 5.1 `semver-trust descriptor build` — the paradigm

```
semver-trust descriptor build --repo . --to <rev>
    (--predecessor <tag> | --new-line)
    --repository <id> --component <name>
    [--interval-mode inception|adoption] [--boundary <oid>]
    [--verification-profile P] [--clock-profile P]
    [--print | --write PATH-OUTSIDE-REPO] [--dry-run]
```

Almost everything is already computed by production code. `MetaPolicyFromTree`
(`internal/verify/metapolicy.go:38`, documented as "the reference a descriptor author
uses to compute matching policy facts") yields, from the tree at `--to`:

- `policy_digest` = `meta.Digest`;
- `trust_material` = `meta.TrustMaterial` (one `treeFileDigest` per declared registry —
  the correct set, by construction);
- `trust_roles` = `meta.TrustRoles` (role → path, named by the fixed role constants) —
  which satisfies `trustRolesValid` (`internal/policy/transition.go:261-274`) by
  construction, so the three-vs-two and role-mismatch traps become untypeable.

`--predecessor <tag>` resolves the two OIDs through `vcs.TagRefs`
(`internal/vcs/tags.go:74`) — `ref_oid` = the observed ref OID (the annotated tag
object), `commit_oid` = the peeled commit — so they cannot be swapped or mistyped;
`--new-line` emits an explicit `null` (never an omission, which the validator rejects).
The operator supplies only the genuinely out-of-band facts: `repository`, `component`,
`interval_mode`/`boundary`, the profile strings.

**Print-by-default**, the bootstrap doc's family invariant: the descriptor goes to stdout,
in front of the human, at the authoring moment — strictly more attention than a
`printf`/`git cat-file` pipeline whose output no one reads. `--write` appends the
canonical bytes to a path **outside** the repo under the writer contract (§3.6), then
re-parses the result through `LoadBootstrapDescriptor` — which refuses in-repo and
symlink targets by the same guard verification uses. The emitted bytes are canonical and
newline-free, so §1's trap is closed for anyone who uses the tool.

This is the release-phase analog of `enroll`: it formats and validates the one artifact
the ceremony currently hand-assembles, and leaves the accountability act (the signed
`release`) to the human.

### 5.2 `semver-trust descriptor validate` — authenticate, and check the round-trip

```
semver-trust descriptor validate --repo . --to <rev> --descriptor PATH
    [--variable-check <owner>/<repo>[:VAR]] [--json]
```

Runs `AuthenticateBootstrapTree` (`internal/verify/verify.go:181`) **and** the full
`checkPolicyTransition` path — because the standalone authentication compares only
`policy_digest` and `trust_material`, while `trust_roles` and the candidate/meta-coverage
checks live in the transition (`SelectPolicyTransition`). With `--variable-check`, it
reads the CI variable back and asserts `sha256(value) == descriptor.Digest()` — the
pre-publish gate of §4.2 as a command. Critically, it compares against the **locally
loaded** descriptor's `Digest()`, not against the bytes it just read back, so the check
does not itself trust the mutable variable channel.

### 5.3 A release preflight check-set

The bootstrap doc's `doctor` already sketches the seeds — `chain/chain-head` and
`remote/platform/release-baseline` (its §5). This proposal fills out a release check-set,
run before any signing, each FAIL naming the abort it preempts and the `fix:` command:

- **range-reviewed / meta-cleared** — the interval `--from <prev> --to <rev>` verifies,
  and no meta-path commit sits below the required level (preempts `under_level_meta_commit`,
  §5.4; `fix:` the exact `attest review` command over the whole interval).
- **verify-time-in-window** — the chosen `--verify-time` predates the signing key's
  expiry (preempts a silent expired-key failure).
- **descriptor-authenticates** — §5.2 as a check.
- **clean-channel** — the range reaches the policy threshold, and the would-be tag/effective
  are reported (so the operator sees `v0.3.0` / T2 before signing).

Read-only, no health verdict, and it ends by printing the real `release` invocation —
it is the on-ramp to `release`, never a substitute, and (as the bootstrap doc argues for
`doctor`) is ADR-recommended *against* CI wiring; `verify` is the CI gate.

### 5.4 `semver-trust reproduce <tag>` — the outsider spot-check as one command

Fetch the attestation refs, extract the recorded instant from the tag's attestation, and
run `verify --chain-head` under that injected clock against an out-of-band descriptor.
This is the bootstrap doc's deferred P3 `reproduce`, now motivated by the transition's
final manual step. It mechanizes the verify-time and out-of-band discipline that §1 and
the reproduction spot-check demand, and — because it is a verification-semantics statement
— it is gated, as the bootstrap doc notes, on conformance vectors for injected-clock
verification.

## 6. Descriptor identity: raw bytes versus canonical bytes

The CI-variable trap (§1) exists because identity is `sha256` over the raw file bytes
(`internal/chain/bootstrap.go:89-92`), so any lossy channel — a stripped newline, CRLF, a
re-indentation — changes it. Two dispositions:

- **Raw bytes (today).** Identity commits to the literal file a human inspected. Brittle
  through any channel that touches the bytes; the mitigation is entirely operational
  (canonical authoring + the round-trip check, §5).
- **Canonical identity.** The repository already has the machinery: `CanonicalizeState` /
  `StateDigest` (`internal/version/canonical.go:44,99`), the ADR-036 JCS-over-JSON
  approach used for version-state digests. The descriptor's value domain is entirely
  JCS-safe (strings, string-maps, string-arrays; `version_predecessor`'s post-validate
  domain is null / object / list), and the field set is already closed by
  `DisallowUnknownFields`. Swapping the `Digest()` body to canonicalize a
  `map[string]any` built from the fields is mechanically small — and it kills the trap at
  the root.

The cost is not code; it is **compatibility**. `Digest()` is bound on-attestation as
`authority_identity` and used to bind a genesis via `AcceptedChainHeadBoundTo`
(`cmd/semver-trust/verify.go:118`), so changing it changes every descriptor's identity:
already-published attestations that pinned the raw-bytes digest would no longer reproduce,
and any digest-pinned conformance vector breaks. That demands a descriptor-profile version
bump and a migration story (dual-read old and new, or a hard cutover).

**Recommendation.** Do both, in order: canonicalize *at authoring time* in `descriptor
build` now — no wire change, since the emitted bytes are already canonical and
newline-free — and open a follow-up ADR to move *identity* to canonical bytes under a
descriptor-profile bump, so the trap eventually dies at the root without breaking today's
chain. This is the document's primary ADR candidate (§9).

## 7. Threat model and risk register

The release family adds exactly one new mutation surface — a descriptor writer — and it
inherits the bootstrap doc's register wholesale:

- **Policy-named paths are a traversal surface** (EN-1). `descriptor build --write` takes a
  filesystem path; it must apply the repo-relative fence and refuse symlink targets, and it
  is additionally constrained to write *outside* the repo (the `LoadBootstrapDescriptor`
  guard, re-run on the result).
- **Tree-not-worktree** (a release-specific EN): the generator's inputs are all tree reads;
  a worktree read would silently produce a descriptor that fails at the tag's tree.
- **The variable-check must not trust the channel** it inspects: it compares the read-back
  value against the locally loaded `Digest()`, not against itself (§5.2).
- **The preflight is read-only and side-effect-free**, so its agent mode is safe by
  construction — the same argument that makes `doctor` agent-safe in the bootstrap doc.

No command signs, stages, or commits, so the trust boundary — a human-signed `release`
past the meta-path gate — is never crossed by this family.

## 8. Steelman and dispositions

A steelman was run against the proposal, in the genre of the bootstrap doc §8 and the
spec repository's `2026-07-04-steelman.md`. The counter-thesis: *the release is the
scheme's single most consequential accountability act; tooling that assembles its inputs
moves attention off the trust path at exactly the wrong moment.*

1. **Descriptor generation erodes the release's accountability.** *Disposition:
   collapses, like the same attack on `enroll`.* The accountability act is the
   **signature** on `release`/`attest`, which no command in this family performs. The
   descriptor is a derived, verifiable artifact — its correctness is checkable against the
   tree — so generating it is not a judgment being rubber-stamped; it is a `git cat-file`
   pipeline being formatted and validated. Print-by-default puts the descriptor in front
   of the human, where the `printf` pipeline never did: strictly *more* attention at the
   moment that matters.
2. **A green preflight becomes a security oracle.** *Disposition: answered by the same
   design that answers it for `doctor`.* No health-verdict summary; every FAIL speaks in
   the verifier's abort vocabulary; the run ends by printing the real `release` command;
   and the accompanying ADR recommends against wiring preflight into CI — `verify` is the
   gate. The standing prediction from the bootstrap doc applies: if preflight ships with a
   "healthy"-shaped summary, screenshots of it will appear as security claims within a
   release cycle.
3. **Premature — a pre-1.0, conformance-gated project polishing the supply side after one
   release.** *Disposition: the release ceremony is not polish; it is the product
   surface.* The scheme exists to make releases trustworthy and reproducible; a ceremony
   this brittle is an adoption blocker, not a convenience gap, and the cost recurs on every
   release and every adopter. The phase boundary (§9) still sits honestly at the
   documentation fixes first, then the descriptor generator whose value is
   semver-trust-proprietary (the digest recipe, the role set, the identity binding) and
   which no generic tool can address.
4. **The identity change is scope creep into the wire.** *Disposition: conceded, and
   deferred behind a version bump.* §6 does not change identity now; it recommends the
   canonical-authoring mitigation immediately and gates the identity change on an ADR and a
   descriptor-profile bump, precisely so the wire is not changed casually.

## 9. Phasing and ADR candidates

- **Now — the documentation PR** (§4). No code. Then re-rank the catalog.
- **P1 — `descriptor build` / `descriptor validate`.** Highest value, mostly reuse
  (`MetaPolicyFromTree`, `vcs.TagRefs`, `LoadBootstrapDescriptor`,
  `AuthenticateBootstrapTree`, `checkPolicyTransition`). Canonical-bytes authoring lands
  here. Drift guard: a test per validate check asserting it wraps the same sentinel verify
  uses.
- **P2 — the release preflight check-set.** Composes with the bootstrap doc's P0 verify-seam
  extraction and its `doctor` shell; the two proposals share that seam, so they should land
  in a coordinated order rather than each carving the single-commit path separately.
- **Deferred — `reproduce`** (conformance-gated on injected-clock vectors, as in the
  bootstrap doc's P3).

ADR candidates (spec repository):

1. **Canonical descriptor identity** (primary) — move `Digest()` from raw bytes to
   JCS-canonical bytes under a descriptor-profile version bump, with a migration story;
   the authoring-time mitigation ships first, without the wire change.
2. **The release family and the generation/accountability line** — the tool builds and
   validates descriptors and diagnoses the range, but never signs, stages, or commits;
   print-by-default; the writer contract for the descriptor file. A section under the
   bootstrap doc's capability-table ADR, not a widening of it.
3. **Preflight is not a CI gate** — recommended against CI wiring; `verify` remains the
   gate — paired with the `doctor` recommendation.

---

## Appendix A — reuse map

| Capability | Status | Location |
|---|---|---|
| Descriptor facts from a tree (the author's reference) | reuse | `internal/verify/metapolicy.go:38` (`MetaPolicyFromTree`) |
| Per-registry blob digest (git blob → sha256 → `sha256:`) | reuse | `internal/verify/metapolicy.go:115` (`treeFileDigest`) |
| Predecessor OIDs (`ref_oid` / `commit_oid`) | reuse | `internal/vcs/tags.go:74` (`TagRefs`) |
| Descriptor load + out-of-band / symlink fence | reuse | `internal/chain/bootstrap.go:104` (`LoadBootstrapDescriptor`) |
| Tree authentication (policy + material) | reuse | `internal/verify/verify.go:181` (`AuthenticateBootstrapTree`) |
| Full transition (roles, candidate, meta-coverage) | reuse | `internal/policy/transition.go`; `internal/verify/verify.go:502` |
| Descriptor identity | reuse / ADR | `internal/chain/bootstrap.go:89` (`Digest`) |
| Genesis-to-descriptor binding | reuse | `internal/chain/predecessor.go` (`AcceptedChainHeadBoundTo`) |
| JCS canonical bytes → sha256 | reuse (§6) | `internal/version/canonical.go:44,99` (`CanonicalizeState` / `StateDigest`) |
| Descriptor writer (atomic, fenced) | net-new (P1) | `internal/descriptor` |

## Appendix B — method note

Produced from: a manual-step catalog of the recurring-release runbook and the real
`v0.2.1 → v0.3.0` transition record; a CLI-surface and internals inventory confirming the
release-ceremony ergonomic layer is greenfield (no `descriptor`/`doctor`/`preflight`/
`reproduce` exists); and an adversarial pass (steelman plus a failure-mode reading of the
descriptor writer). The dispositions — the identity change deferred behind a version bump,
the documentation fixes accelerated, the writer constrained to outside the repo — are
reflected throughout, with §7–§8 preserving the audit trail. It is the sibling this
document's own header names: the bootstrap-family method, carried from the setup phase into
the release phase it deferred.
