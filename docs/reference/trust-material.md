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
statements. Generate both as plain SSH ed25519 keys:

```sh
# Commit signing (skip if you already sign commits with SSH)
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_signing -C 'you@example.com commit signing'

# Attestation signing (dedicated; note the different file)
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
  policy keeps those merges honestly machine-class (see the
  legacy-adoption guide, forthcoming in this docs set).

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

1. Contributor generates a signing key and configures git to sign with it
   (see the contributor guide, forthcoming).
2. Contributor opens a PR adding one line to `.semver-trust/allowed_signers`
   with their principal and public key.
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
