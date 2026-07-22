<!-- SPDX-License-Identifier: Apache-2.0 -->
# The policy file

`.semver-trust/policy.toml` is the root of trust: every verification decision —
what counts as a human, which paths guard the system, what trust level a clean
release requires — derives from this one committed file. This page documents
every field the reference implementation accepts and how to choose the values
that matter. The normative schema is
[spec §9](https://github.com/semver-trust/spec/blob/main/spec/semver-trust.md#9-policy-file);
because the file *is* the root of trust, the parser is strict — an unknown
field, a malformed value, or a declared-but-empty path is an error, never a
warning (trust-shaped-but-malformed input is invalid everywhere).

Validate and inspect any policy with:

```sh
semver-trust policy validate --repo .    # parse + digest
semver-trust policy explain --repo .     # the decision table in effect
```

## `[policy]` — threshold and strategy

```toml
[policy]
version   = "0.1"        # policy schema version (required)
threshold = "T2"         # minimum trust level for the clean channel
strategy  = "demote"     # what happens below threshold: demote | inflate
adoption_boundary = "v0.9.4"   # optional — legacy adoption only (ADR-026/028)
```

- **`threshold`** — the **hard clean-channel accountability gate** (spec
  repository ADR-032): a release whose effective trust is below it MUST NOT enter
  the clean channel, and that check is applied *before* the §6.4 blast/differ
  table, as part of the release decision (and bound into the release attestation
  for deterministic replay). Below the threshold, `strategy` decides the shape:
  `demote` keeps the semantically correct bump but confines the release to the
  trust pre-release channel (`v1.4.0-t1.1`); `inflate` escalates the bump itself
  (PATCH→MINOR or →MAJOR) so default ranges do not auto-adopt (spec §6.3). The
  portable baseline is **T2** (T1 is not in the clean profile before empirical
  agent-review evidence). `verify` *reports* threshold eligibility — a
  clean-channel line in its output — but does not itself gate; the gate lives in
  the release decision, not in verification.
- **`adoption_boundary`** — a commit (SHA or tag) before which history is
  exempt from verification. **Greenfield repositories never need this**; it
  exists for legacy adoption where early history is genuinely unverifiable
  (see
  [adopting on an existing repository](../guides/adopt-legacy-github.md)). Three
  properties bind it (spec repository ADR-026): it is *policy-pinned* — moving it
  is a meta-path commit at the required level; it is *disclosed* — every report
  and release attestation marks a boundary-anchored range; and it is *exempt,
  never laundered* — pre-boundary history makes no claim at all (out of scope,
  not T0). Under the opt-in **v0.10 path** (spec repository ADR-028) the
  boundary's *authority* is an out-of-band **bootstrap descriptor** supplied with
  `--bootstrap-descriptor` — an authenticated document the verifier holds from
  *outside* the repository (the loader rejects any in-repo path). The flag
  *supplies* that external authority; it does not let a verifier *move* the
  boundary — the in-policy value must match the descriptor, and neither the repo
  nor the caller can move it unilaterally. Absent a descriptor, the policy-pinned
  value governs exactly as above.

### Choosing threshold and strategy

Count the accountable humans your project can honestly produce per release,
and set the threshold to that number — not to the number you aspire to:

- **Solo maintainer (with or without agents): `T2`.** T2 means exactly one
  accountable human stood behind the change, in either role. Agent-authored
  commits reach it through your own signed review — the self-review exclusion
  prevents one human counting as *two*, never as *one* (spec repository
  ADR-025). **T3 is unreachable for a solo project**: it requires two distinct
  verified humans, and no configuration can honestly conjure a second one.
  Setting `threshold = "T3"` solo means every release lands in the pre-release
  channel forever.
- **Two-plus maintainers: `T2` or `T3`.** `T3` demands author and reviewer be
  different verified identities on every release-critical path. Choose it when
  you actually operate that way on every change, not merely when you want to
  claim it.
- **`demote` over `inflate`, almost always** (the spec recommends it). Demote
  preserves what MAJOR/MINOR/PATCH mean — the API-compatibility promise stays
  intact, and the trust shortfall is expressed in the pre-release slot, where
  consumers opt in explicitly and post-hoc review can promote the release to
  the clean channel later without changing a byte of source (spec §7.3).
  Inflate expresses the shortfall in the precedence-relevant part of the
  version instead; some organizations want that, at the cost of diluting
  MAJOR's "your code must change" signal and forcing migration review where
  no API changed.

## `[meta]` — the paths that guard the system

```toml
[meta]
paths = [
  ".semver-trust/**",
  ".github/workflows/**",
  ".github/rulesets/**",
  "scripts/merge-pr.sh",
]
required_level = "T2"
```

Meta-paths are the files that could reclassify everything else: the policy and
trust material themselves, CI that gates merges, branch-protection artifacts,
the merge script. A commit touching any of them must *individually* reach
`required_level` — the config protects the system (spec §5.4).

**Do not lock yourself out.** `required_level` must be a level your project
can actually produce. A solo maintainer who sets `required_level = "T3"` can
never again change the policy file — including to fix that mistake — without
recruiting a second human. The safe pattern is `required_level` equal to your
threshold (T2 for a solo project), covering at minimum `.semver-trust/**` plus
whatever automation can alter what merges.

## `[identity]` — who counts as whom

```toml
[identity]
attestation_signers = ".semver-trust/attestation_signers"

[identity.human]
allowed_signers = ".semver-trust/allowed_signers"
gpg_keyring     = ".semver-trust/gpg-keyring.asc"

[identity.agent]
bot_accounts = ["noreply@github.com"]
```

- **`allowed_signers`** — the SSH commit-signer registry (human identities).
- **`gpg_keyring`** — the armored OpenPGP keyring, the GPG counterpart for
  repositories with GPG-signed history.
- **`attestation_signers`** — the *separate* registry of keys allowed to sign
  review and release attestations (least privilege — spec repository ADR-022).
- **`bot_accounts`** — signer identities to classify as machine rather than
  human. The canonical entry is GitHub's web-flow key identity
  (`noreply@github.com`), which signs web-UI merge commits: enrolling the key
  makes those merges *verifiable*, listing its identity here keeps them
  honestly *agent-class* rather than silently human. Omit it entirely if the
  repository has no web-UI merges — a solo repo that merges locally and signs
  has no machine signer to classify.

File formats and enrollment flow live in
[trust material](trust-material.md). Declaring these paths in the policy lets
`verify`, `release`, and `promote` default their trust-material flags from the
target commit's tree — the whole repository verifies flag-free. On the default
v0.3 path an explicitly supplied `--allowed-signers` / `--gpg-keyring` /
`--attestation-signers` still overrides the policy. In v0.10 **descriptor mode**,
though, those overrides are **rejected fail-closed**: the bootstrap descriptor
pins the trust material by digest from the tree, so honoring a filesystem override
would defeat that pinning — a key-substitution bypass (spec repository ADR-028).
The material used for verification must be the material the descriptor pins.

## `[trailers]`, `[graph]`, `[evidence]`

```toml
[trailers]
require = true          # protected-branch commits must carry Provenance:

[graph]
adapter = "none"        # single-module repo; "gomod" reads the Go module graph

[evidence.go]
compat = "apidiff"      # semantic-floor evidence provider for Go APIs
```

- **`[trailers] require`** — whether an absent `Provenance:` trailer is a
  policy violation (see [trailers](trailers.md)). Leave it `true`; the entire
  authorship half of classification reads these.
- **`[graph] adapter`** — how scopes and their dependencies are discovered for
  weakest-link flooring (spec §5.3). `none` means one implicit scope covering
  the whole repository — right for single-module projects. `gomod` derives the
  graph from Go module metadata.
- **`[evidence.*]`** — per-ecosystem evidence providers feeding the semantic
  floor and blast radius (spec §6). Anything a provider cannot compute is
  reported *unavailable*, never fabricated.

## A minimal starting policy

For a new single-module repository with one maintainer:

```toml
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
```

The [bootstrap guide](../guides/bootstrap-github.md) walks this file into a
verified first release.

## See also

- [Trust material](trust-material.md) — the files these fields point at.
- [Reading verify output](verify-output.md) — how policy decisions surface.
- This repository's live policy:
  [`.semver-trust/policy.toml`](../../.semver-trust/policy.toml).
