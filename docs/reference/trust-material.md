<!-- SPDX-License-Identifier: Apache-2.0 -->
# Trust material

The `.semver-trust/` directory holds everything verification trusts: the
[policy](policy.md) and the registries of keys behind it. All of it is
committed — a fresh clone carries its own verification roots, and nothing is
fetched from the network at verify time. This page documents each file's
format, the two-key model, and the enrollment flow.

```text
.semver-trust/
├── policy.toml            the root of trust (see reference/policy.md)
├── allowed_signers        SSH commit-signer registry (human identities)
├── attestation_signers    attestation-signer registry (separate, ADR-022)
└── gpg-keyring.asc        armored OpenPGP keyring (optional; GPG-signed history)
```

Because the policy names these paths (spec §9), `verify`, `release`, and
`promote` read them **from the target commit's tree** — not from your working
directory. That has two consequences worth knowing: commands run flag-free
against any commit whose tree carries its material, and an enrollment only
takes effect for ranges whose tip contains the enrolling commit. An explicit
flag (`--allowed-signers`, `--gpg-keyring`, `--attestation-signers`) always
overrides the tree, for the cases where material must come from out-of-band.

## Two keys, two purposes

A repository under the scheme distinguishes *committing* from *attesting*:

| Key | Signs | Registry | Namespace |
|---|---|---|---|
| Commit-signing key | Your commits (and tags) | `allowed_signers` (or the GPG keyring) | `git` |
| Attestation key | Review and release attestations | `attestation_signers` | `attestation@semver-trust.dev` |

Keeping them separate is least privilege (spec repository ADR-022): the
attestation key asserts *"I reviewed this range"* and *"I stand behind this
release"* — a stolen commit key must not be able to fabricate those
statements. The two keys reuse differently:

- **Commit-signing key — reuse yours.** It is your ordinary git signing identity;
  if you already sign commits (SSH or GPG), reuse that key rather than minting a
  new one per repository. Find it with `git config --get user.signingkey`,
  `ls -1 ~/.ssh/*.pub`, `ssh-add -L`, or (GPG) `gpg --list-secret-keys
  --keyid-format long`. Generate one only if you have none:

  ```sh
  ssh-keygen -t ed25519 -f ~/.ssh/semver-trust-commit -C 'you@example.com commit signing'
  ```

- **Attestation key — always dedicated.** A fresh SSH ed25519 key, distinct from
  the commit key and never a GPG key (attestations are SSHSIG); `enroll`, `setup`,
  and `doctor` refuse a key that serves both roles:

  ```sh
  ssh-keygen -t ed25519 -f ~/.ssh/semver-trust-attest -C 'semver-trust attestation signing'
  ```

## `allowed_signers` — the commit-signer registry

Standard OpenSSH `allowed_signers` format
(`man ssh-keygen`, ALLOWED SIGNERS): one line per identity —
an email (the *principal*), optional scoping options, then the public key:

```text
alice@example.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

The principal is what verification reports as the commit's verified identity;
`namespaces="git"` scopes the key to commit/tag signatures (git signs in the
`git` namespace).

## `attestation_signers` — the attestation registry

Same file format, different namespace — and that difference is load-bearing:

```text
alice@example.com namespaces="attestation@semver-trust.dev" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

A key enrolled here can sign attestations and nothing else; a commit-signing
key that strays into this file would gain attestation power, so don't reuse
one. Append your enrollment line directly from the public key file:

```sh
echo "you@example.com namespaces=\"attestation@semver-trust.dev\" $(cut -d' ' -f1,2 ~/.ssh/semver-trust-attest.pub)" \
  >> .semver-trust/attestation_signers
```

## `gpg-keyring.asc` — the OpenPGP counterpart

An ASCII-armored keyring holding the OpenPGP public keys behind any GPG-signed
commits in history. Repositories whose contributors sign with SSH from day one
never need it. Two situations do:

- **GPG-signing contributors** — export and append their public keys:
  `gpg --armor --export KEYID >> .semver-trust/gpg-keyring.asc`.
- **GitHub web-UI history** — merges made through GitHub's web interface are
  signed by GitHub's own *web-flow* key, published at
  <https://github.com/web-flow.gpg>. Enrolling it makes that history
  verifiable; pairing it with `bot_accounts = ["noreply@github.com"]` in the
  policy keeps those merges honestly machine-class (see
  [adopting on an existing repository](../guides/adopt-legacy-github.md)).

A key's identity, for classification purposes, is the email in its primary
user ID. There is no partial credit here: a signature by a key that is in no
registry is not "less trusted" — it aborts verification (unverifiable is never
T0; see [reading verify output](verify-output.md)).

## Enrollment is the accountability assertion

Adding a line to a registry is not bookkeeping — it is the moment a person
becomes accountable under the scheme. The commit that enrolls a key says "this
identity's signatures now count," which is exactly why `.semver-trust/**`
belongs in the policy's meta-paths: an enrollment commit must itself meet the
required trust level, reviewed like anything else that can change what
verification means.

The flow for a new contributor:

1. Contributor configures this clone with `semver-trust setup` (reusing an
   existing signing key, or a new one) and generates their enrollment with
   `semver-trust enroll` — an SSH commit key into `allowed_signers`
   (`enroll --commit-key <key>.pub`), or a GPG key into the `gpg_keyring`
   (`enroll --gpg-pubkey <key>.asc`). The key family must match what the policy's
   `[identity.human]` declares; see the [contributor guide](../guides/contributor.md).
2. Contributor opens a PR adding that trust material to the registry the policy
   names.
3. A maintainer reviews the line against out-of-band knowledge of the person
   (this is the human judgment the cryptography anchors) and merges it through
   the normal meta-path gate.
4. From the enrolling commit forward, that identity's signatures verify.

Removal is the same operation in reverse, with the same gate — and one
consequence to understand before you reach for it. Registries are read from
the tree at the *tip* of the range being verified, so removing a key makes
that identity's signatures unverifiable in any future-verified range that
still contains its commits. Remove a key that should never have been trusted
(compromise), and expect the affected ranges to need attention; for an
ordinary departure, leave the enrollment in place — an enrolled key that no
longer signs anything costs nothing.

## See also

- [The policy file](policy.md) — the fields that name these files.
- [Attestation refs](attestation-refs.md) — where signed attestations live.
- [The documentation index](../README.md) — the persona guides that walk this
  material end to end.
