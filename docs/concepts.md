<!-- SPDX-License-Identifier: Apache-2.0 -->
# SemVer-Trust concepts

This is the plain-language guide to what SemVer-Trust is, why it exists, and
what it does and does not promise. It assumes you know semantic versioning and
git; it assumes nothing about the scheme itself. The
[specification](https://github.com/semver-trust/spec) is the normative source;
this document is the on-ramp.

## The problem

For twenty years, a version bump has been a promise. `1.4.2 → 1.4.3` says "drop
this in, nothing will break." `1.4.2 → 1.5.0` says "new things, but your code
still works." That promise was only ever as good as the work behind it — but
the work behind it used to be legible. A human wrote the change, a human
reviewed it, a changelog described it, a green review badge vouched for it. The
signals were cheap to *read* and expensive to *fake*, so we trusted them.

Coding agents inverted that economy. A plausible diff, a well-formed commit
message, a passing test suite, a tidy changelog entry — all of it is now cheap
to *produce* at any volume. The signals did not change. Their meaning collapsed.
A green checkmark no longer tells you a person looked at the code; a `fix:`
commit no longer tells you a person decided it was safe; `1.4.3` no longer tells
you anyone stands behind the claim that it is a safe drop-in. The version string
still makes the promise. Nothing in it now says who is accountable for keeping
it.

SemVer-Trust exists to put that missing evidence back into the version — without
breaking a single existing tool.

## What SemVer-Trust does

It attaches a **trust level** — `T0`, `T1`, `T2`, or `T3` — to a release,
computed from cryptographic evidence of who is accountable for the code, and it
encodes that level in the version string using nothing but ordinary SemVer.

The trick is where it puts the level. SemVer already has a "not-final-yet" slot:
the pre-release identifier, the part after a hyphen (`1.4.0-rc.1`). By
precedence rules that every resolver already implements, `1.4.0-rc.1` sorts
*below* `1.4.0`, and default dependency ranges skip pre-releases. SemVer-Trust
uses a reserved pre-release identifier — `t` plus the level digit — for the same
effect:

```
v1.4.0-t1.1   <   v1.4.0
```

A release that could not muster the evidence for a clean version goes out as
`v1.4.0-t1.1` instead. In Go modules, npm, and Cargo alike, default resolution
will not select it. **Low-trust releases become opt-in by construction, with
zero consumer-side tooling.** A team that never installs SemVer-Trust still
never auto-adopts an under-evidenced release from a dependency that uses it —
the ordering does the work. Adoption is entirely on the producer's side.

## Trust levels order accountability, not risk

This is the idea most worth getting right, so it is worth stating plainly and
then defending.

A trust level counts **independent accountable humans** bound to a change:

- **T3** — two distinct accountable humans: one verified author, a different
  verified reviewer. Authored by one person, independently reviewed by another.
- **T2** — exactly one accountable human, in either role. One person stands
  behind it (they wrote it, or they reviewed what an agent produced).
- **T1** — no accountable human, but an independent agent reviewed it. Fully
  autonomous, with machine corroboration from a separate agent.
- **T0** — no accountable human and no independent review. Fully autonomous.

`T0` is not a failure and not an error. It is an honest, precise statement: *no
person has yet put their name on this change.* It is a perfectly valid thing for
a release to be; it simply travels in the opt-in channel until someone does.
(The state where verification *cannot complete* — a broken signature, a missing
attestation — is a different thing entirely, covered below: that aborts, and is
never reported as T0.)

The levels rank **accountability, not risk**. They do not claim that a T3
release has fewer bugs than a T1 one. A meticulous solo maintainer's T2 release,
or a well-corroborated T1, may be empirically safer than a T3 that two people
rubber-stamped in ninety seconds. The scheme refuses to pretend otherwise: it
measures the one thing cryptography can actually establish — *who has asserted
they stand behind this* — and leaves the mapping from accountability to risk to
policy, which gets the full evidence to work with. This is a deliberate design
commitment (specification
[ADR-019](https://github.com/semver-trust/spec/blob/main/docs/adr/0019-trust-levels-order-accountability-not-risk.md)),
and it is what keeps the levels honest: they only ever claim the count of humans,
which is exactly what they can prove.

## How a level is computed in practice

Every level is built up from individual commits and then floored together.

**Per commit, an authorship class.** Every commit on a protected branch must be
signed. The verified signer's identity — a human key or a machine identity — is
the primary signal, refined (never overridden) by the commit's `Provenance:`
trailer. A commit signed by a person's key with `Provenance: human` is
human-authored; one signed by a CI machine identity with `Provenance: agent` is
agent-authored. If the signature and the trailer disagree — a machine-signed
commit *claiming* `Provenance: human` — the claim is treated as absent and the
commit floors to agent-authored. Unverifiable claims of human authorship earn
nothing.

**Per commit, a review class.** Review happens on platforms, outside git, so it
is captured at merge time as a signed **review attestation** naming the
reviewed commits, the reviewer's identity and class (human or agent), and the
verdict. The verifier locates and cryptographically checks that attestation; a
human reviewer's signature adds a human, an independent agent reviewer's adds
machine corroboration.

**The pair maps to a level.** Authorship class × review class → `T0`–`T3` by a
fixed matrix (specification §3.2). Agent-authored with no review is T0; the same
commit with an independent agent review is T1; with a human review (even from
the same person who did the agent-assisted authoring) it reaches T2; human
authored *and* independently reviewed by a different human is T3.

**Weakest link, then propagation.** A release covers a range of commits. Its
**own trust** for a given part of the codebase is the *minimum* level over every
commit that touched that part — a floor, never an average. One T0 commit floors
its scope exactly like a thousand of them; there is no "trivial change doesn't
count" loophole, because that loophole is precisely where a payload would hide.
Scopes are then not independent: if component A consumes component B inside the
same workspace, A's **effective trust** is floored by B's. Risk cannot launder
itself into a shared library while the consumer's own scope stays pristine.

**The decision.** Effective trust and a blast-radius estimate feed the policy's
decision table (specification §6.4). The table says, per level and blast, whether
the release goes out **clean** (the plain version) or gets **demoted** to the
trust pre-release channel until more evidence arrives. The semantic floor is
honored unconditionally on top of this — a change that breaks the public API is a
MAJOR bump no matter how trusted it is; trust decides the *channel*, never the
*compatibility meaning* of the number.

## The pre-release channel and promotion

A demoted release is not a dead end. It is the release, in a waiting room.

The pre-release channel generalizes the old release-candidate pattern: publish,
let evidence accumulate, promote. When new evidence lands — a human reviews the
code after the fact, a soak test passes, an audit completes — the release can be
**promoted to the clean channel without changing a single line of source.** The
promotion cuts the clean tag (`v1.4.0`) on the *identical commit* the
pre-release pointed at, and emits a fresh attestation that supersedes the old
decision.

That last part is a load-bearing principle: **the record is superseded, never
mutated.** Trust evolves after a version string is frozen — evidence arrives
late, or a review is later revoked — so the living record cannot be the
immutable tag. It is the attestation. The tag records trust *at release time*;
the chain of attestations records trust *as it stands now*. Demotion works the
same way in reverse: you cannot un-publish a shipped version, but you can publish
a superseding attestation (and, where warranted, a security advisory) that says
the evidence no longer holds.

## What this accomplishes

**Up close, for one release:** every release carries portable, cryptographic
evidence of exactly who stood behind it, at what level, computed by a public
algorithm from public inputs. It is reproducible — this repository's own
`v0.1.0` is the proof: a stranger can clone it, fetch the attestations, inject
the recorded verification instant, and re-derive the identical decision from
public material alone. The trust claim is not something you take the maintainer's
word for. You re-run it.

**At a distance, for the ecosystem:** a version number is the cheapest, most
universal trust signal software has — every package manager already reads it.
SemVer-Trust recalibrates that signal for a world where code is cheap and
accountability is the scarce thing. It is **accountability infrastructure
first** — a verifiable, portable record of who answers for a change — and a risk
signal only second, and only to the extent evidence ever bears that out. If the
empirical link between trust levels and defect rates turns out weak, the scheme
still stands on the first claim: it makes accountability legible again, which is
the thing the agent era took away.

## What it deliberately does not claim

An honest scheme is precise about its own limits.

- **It cannot detect a human running an agent under their own key.** If you run
  an agent locally and commit with your own signature, the scheme classifies the
  commit as human-authored — as an *accountability assertion by you*, the signer.
  T2 and T3 mean "a human stands behind this," never "a human typed this." This
  is the identity-laundering limit, and it is stated in the open (specification
  Principle 2 and the §11 threat model) rather than papered over. The mitigation
  is policy and audit, not a cryptographic claim the scheme cannot honestly make.
- **It does not judge review quality.** A distinct-identity human review counts
  toward T3 whether it was thorough or a rubber stamp. Approval latency and
  comment depth are measurable but gameable, and are out of scope by design. The
  scheme records *that* an accountable human reviewed; it does not grade *how
  well*.
- **Unverifiable is never T0.** T0 is a *verified fact about a verified commit*:
  we checked, and no accountable human is bound to it. When verification cannot
  complete — a signature fails, a required attestation is missing — the verifier
  **aborts** and names the step it failed at. It does not silently degrade a
  broken proof into a low-but-passing level. Missing evidence is a hole, not a
  score.
- **It makes no correctness guarantee.** A T3 release can still be wrong. Trust
  bounds *provenance and review evidence*, not runtime behavior. The scheme
  tracks who is accountable; it does not promise the code is correct.

## A worked example

Here is the scheme end to end, in plain words. (This retells specification
Appendix A.)

A monorepo has three components: `auth` and `billing`, both of which depend on a
shared `common` library. Policy sets the threshold at T2 with the `demote`
strategy.

1. Since its last release, `common` got three commits from a CI agent — machine
   identity, `Provenance: agent`, no review. Weakest link over those commits
   makes `common`'s own trust **T0**. It ships as `common/v0.9.0-t0.1`: a
   real release, in the opt-in channel, honestly labeled.

2. `auth` got five commits, each written by a human and reviewed by a different
   human — own trust **T3** — plus some generated code that a verified
   derivation proof re-derives byte-for-byte from a human-reviewed spec, so the
   generated files inherit the spec's T3 too. But `auth` consumes `common`, and
   effective trust floors through the dependency: `min(T3, T0) = T0`. So `auth`
   also ships to the pre-release channel, `auth/v1.4.0-t0.1`, with its
   attestation recording that `common` is what floored it. The T3 work isn't
   lost; it is being held back by its weakest dependency, and the record says
   exactly which one.

3. A maintainer reviews `common`'s three agent commits after the fact and signs
   a review attestation. Re-evaluating `common`: an accountable human now stands
   behind it, so its own trust rises to **T2**, meeting the threshold. `common`
   is **promoted** — the clean tag `common/v0.9.0` lands on the identical commit,
   with a superseding attestation. No source changed; only evidence did.

4. Because `auth`'s attestation pinned `common` as its floor source, that
   promotion makes `auth` re-evaluable. Now `effective(auth) = min(T3, T2) = T2`,
   which clears the threshold, so `auth/v1.4.0` is promoted onto its same
   commit. The whole chain reached the clean channel without a single rebuild —
   evidence, not code, unblocked it.

5. Later, a `billing` release includes one commit that edits the policy file
   itself. The policy is the root of trust, so commits touching it must meet the
   maximum required level. This one doesn't. Verification **aborts** — not
   demotes, aborts — and no tag is cut until the policy change is properly
   reviewed. The configuration protects the system, so the system protects the
   configuration.

That is the whole scheme: read the provenance, floor it honestly, encode it
where existing tools already understand it, and let evidence — not source
churn — move a release toward the clean channel.
