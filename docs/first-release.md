<!-- SPDX-License-Identifier: Apache-2.0 -->
# First trust-tagged release — the GO-061 ceremony

This runbook cuts the repository's first release with the tooling it built
(implementation plan GO-061, the overall exit criterion): a release whose
decision an outsider can reproduce from public material alone. Steps marked
**MANUAL** are the maintainer's accountability acts and cannot be delegated;
everything else is scripted or already committed.

## Trust material (already committed)

- `.semver-trust/policy.toml` — threshold T2, strategy demote, meta-paths at
  T2, `noreply@github.com` classified as a machine identity.
- `.semver-trust/gpg-keyring.asc` — the injected commit-verification
  keyring: the maintainer's two public keys plus GitHub's web-flow key
  (fetched from <https://github.com/web-flow.gpg>), which signs every
  web-UI merge commit including the repository's root. Nothing in this
  history is unverifiable; web-flow merges classify honestly as
  machine-signed and untrailered (ambiguous → T0) and are lifted by
  post-hoc review like any other commit (§7.3, Appendix A step 3).

Note on clocks: the maintainer's 2026-07 temporary key expires 2026-08-01,
so verification instants for history signed by it must predate the expiry.
That is what the injected clock is for (ADR-018): the release attestation
records its timestamp, and a reproducing outsider injects **that** instant,
not their own wall clock.

## 1. MANUAL — attestation signing key

```sh
ssh-keygen -t ed25519 -f ~/.ssh/semver-trust-attest -N '' \
  -C 'semver-trust attestation signing'
echo "brad.pinter@gmail.com namespaces=\"attestation@semver-trust.dev\" $(cut -d' ' -f1,2 ~/.ssh/semver-trust-attest.pub)" \
  >> .semver-trust/attestation_signers
```

Commit the registry line (a PR like any other): enrolling the key is the
accountability assertion — the private key never leaves the maintainer.

## 2. MANUAL — the post-hoc review (Appendix A step 3)

Review the history you are about to attest — the attestation asserts *you
stand behind it* (P2). Then:

```sh
semver-trust attest review \
  --repo . --from '' --to <TO-sha> \
  --reviewer brad.pinter@gmail.com --verdict approved \
  --pr https://github.com/semver-trust/semver-trust-go/pulls \
  --key ~/.ssh/semver-trust-attest --store
```

This lifts agent-authored commits to T2 (agent + distinct human review) and
the meta-path-touching commits past the required level, clearing §5.4.

Push the attestation refs so outsiders can fetch them:

```sh
git push upstream 'refs/attestations/*:refs/attestations/*'
```

## 3. Pre-flight (either of us)

```sh
semver-trust verify --repo . --from '' --to <TO-sha> \
  --gpg-keyring .semver-trust/gpg-keyring.asc \
  --attestation-signers .semver-trust/attestation_signers \
  --verify-time <now, RFC3339>
```

Must complete §10 steps 1–7 with own/effective ≥ T2. If it aborts, stop:
the abort reason is the truth, and the release must not be forced.

## 4. MANUAL — the release

```sh
semver-trust release \
  --repo . --from '' --to <TO-sha> \
  --claimed-bump minor --blast <low|moderate|high — your call, recorded as operator-supplied> \
  --gpg-keyring .semver-trust/gpg-keyring.asc \
  --attestation-signers .semver-trust/attestation_signers \
  --tag-key ~/.ssh/semver-trust-attest --attest-key ~/.ssh/semver-trust-attest \
  --verify-time <now, RFC3339>
git push upstream 'refs/tags/<the tag>'
git push upstream 'refs/attestations/*:refs/attestations/*'
```

At T2 effective with threshold T2, the §6.4 table gives: blast low →
clean; moderate → clean only with a differ proof for a PATCH claim (a
MINOR claim passes); high → pre-release. A pre-release outcome is not a
failure — it is the honest channel, promotable later (§7.3).

## 5. Reproduce like an outsider (the flagship claim)

```sh
git clone https://github.com/semver-trust/semver-trust-go /tmp/fresh && cd /tmp/fresh
git fetch origin 'refs/attestations/*:refs/attestations/*'
go run ./cmd/semver-trust verify --repo . --from '' --to <the tag> \
  --gpg-keyring .semver-trust/gpg-keyring.asc \
  --attestation-signers .semver-trust/attestation_signers \
  --verify-time <the attestation's recorded timestamp>
```

Same inputs, same instant, same decision — from public material alone.
