<!-- SPDX-License-Identifier: Apache-2.0 -->
# Attestation refs

Review and release attestations are signed statements (DSSE envelopes,
SSHSIG-signed — spec §8) stored *in the repository itself*, as git blobs
addressed by refs under a dedicated namespace. No platform API, no sidecar
service: if you can `git fetch`, you can fetch the evidence.

## Layout

```text
refs/attestations/<subject>/<digest12>
```

- **`<subject>`** — what the attestation is about: a tag name (`v0.2.0`) for
  release attestations, or the range/commit subject a review covers.
- **`<digest12>`** — the first 12 hex digits of the envelope's content digest,
  which makes the ref content-addressed and collision-evident.

A real one, from this repository:

```text
refs/attestations/v0.2.0/53455cd3f5f9399300db6b4c
```

## Moving them

The refs travel over plain refspecs — they are not fetched by default, so name
the namespace explicitly:

```sh
# Publish local attestations (after `attest review --store` or `release`)
git push origin 'refs/attestations/*:refs/attestations/*'

# Fetch everything published (a fresh clone has none until you do this)
git fetch origin 'refs/attestations/*:refs/attestations/*'

# See what you have
git for-each-ref refs/attestations/
```

In a clone you work in over time, configure the **fetch** side once so every
future `git fetch`/`pull` carries evidence automatically:

```sh
git config --add remote.origin.fetch 'refs/attestations/*:refs/attestations/*'
```

Deliberately non-force (no leading `+`): attestation refs are content-addressed
and append-only ([supersession, not mutation](#supersession-not-mutation)), so a
legitimately fetched ref never changes — a remote-side ref that *did* change
should surface as a visible fetch refusal, not a silent local replacement. The
**push** side stays an explicit command: writing a push refspec would change
what a bare `git push` means.

The error `no release attestation ref found under refs/attestations/<tag>/`
almost always means the push above didn't happen — the tag traveled, its
evidence didn't. (This repository's release workflow fails with exactly that
message, by design, when a tag is pushed before its attestation refs.)

## The store is never the trust anchor

Anyone who can push refs can push an envelope; storage implies nothing. Every
attestation is verified from first principles when read — signature against
the [attestation-signer registry](trust-material.md), subject against the
commit it claims, payload against the schema — so a forged or tampered
envelope is rejected no matter how it arrived (spec §8.2). Push access to
`refs/attestations/*` is not a trust decision; enrollment in
`attestation_signers` is.

## Supersession, not mutation

Attestations are immutable once stored. New evidence about the same subject —
a promotion decision after post-hoc review, a re-decision at the same commit —
is a *new* envelope whose `supersedes` field names the ref of the one it
replaces (spec §7.3). The chain preserves the full history of what was claimed
and when; nothing is ever edited in place.

## See also

- [Trust material](trust-material.md) — who may sign attestations.
- [Reading verify output](verify-output.md) — how attestation evidence shows up.
- The release ceremony: this repository's [release runbook](../release-runbook.md).
