<!-- SPDX-License-Identifier: Apache-2.0 -->
# Adopting SemVer-Trust on GitLab

The verification engine is pure local git — it opens your clone, reads
commits, signatures, trailers, and attestation refs, and calls no platform
API. Adopting on GitLab is therefore mostly a matter of substituting the
GitHub-specific *surroundings*, and this guide maps each one. Claims marked
**⚠ verify on your instance** have not been empirically confirmed by this
project; everything else is verified against GitLab's documentation or this
implementation's source. The [open-questions register](#open-questions-register)
at the end collects them.

The complete GitHub coupling, for perspective — everything *not* on this list
works unchanged:

| GitHub piece | Role | GitLab substitution |
|---|---|---|
| `bot_accounts = ["noreply@github.com"]` in policy | classifies web-UI merge signatures as machine | the instance signing identity, default `noreply@gitlab.com` (§identity below) |
| web-flow key in `gpg-keyring.asc` | verifies web-UI merges | the instance web-signing key (§identity below) |
| `.github/workflows/*` + composite action | CI gates + release publishing | `.gitlab-ci.yml` jobs (§ci below) |
| rulesets JSON + `check-rulesets.py` | branch protection as artifacts | protected branches + push rules (§enforcement below) |
| `scripts/merge-pr.sh` (gh preamble) | local signed merges | same git core; `glab`/MR API preamble |
| goreleaser `github:` block, dependabot | publishing, dep updates | goreleaser GitLab mode; Renovate/GitLab dependency scanning |

## What works unchanged

Every CLI command — `verify`, `release`, `promote`, `attest review`,
`policy`, the plain-mode tag commands — operates on the local repository and
its committed trust material. Attestations travel as plain git refs
([attestation refs](../reference/attestation-refs.md)):

```sh
git push origin 'refs/attestations/*:refs/attestations/*'
git fetch origin 'refs/attestations/*:refs/attestations/*'
```

In a clone you work in over time, set the fetch side once
(`git config --add remote.origin.fetch 'refs/attestations/*:refs/attestations/*'`)
so it rides every `git fetch`/`pull`
([details](../reference/attestation-refs.md#moving-them)); an ephemeral CI
checkout keeps the explicit fetch below.

GitLab hides and write-protects only its *own* internal ref namespaces
(`refs/merge-requests/*`, `refs/keep-around/*`, `refs/pipelines/*`) — pushes
to those are denied with "deny updating a hidden ref." An arbitrary namespace
like `refs/attestations/*` is expected to pass. **⚠ verify on your instance**
— GitLab does not document a guarantee for custom namespaces, so run the
30-second smoke test once against a scratch project:

```sh
git push origin "$(git rev-parse HEAD):refs/attestations/smoke"   # must succeed
git ls-remote origin 'refs/attestations/*'                         # must list it (advertisement)
git push origin --delete refs/attestations/smoke                   # clean up
```

If the push is rejected on a self-managed instance, ask your administrator
about server-side `receive.hideRefs` configuration.

## Identity: the instance signing key

GitLab's analog of GitHub's web-flow key is an **instance-wide signing key**:
commits created through the web UI — Web Editor, Web IDE, **and merge-request
operations including squashes and rebases** — are signed with a key
configured for the instance, with committer identity `GitLab
<noreply@gitlab.com>` by default (self-managed instances can configure both).
Web-based commit signing reached general availability for self-managed in
GitLab 17.0 and for GitLab.com in 18.10; on older instances web commits may
simply be *unsigned* — which changes your adoption math (see below).

The same two-entry pattern as GitHub applies
([why both](adopt-legacy-github.md#3-the-web-flow-key-specifically)):

```toml
[identity.agent]
bot_accounts = ["noreply@gitlab.com"]   # or your instance's configured identity
```

plus the instance public key appended to `.semver-trust/gpg-keyring.asc`.
**⚠ verify on your instance**: unlike GitHub's `https://github.com/web-flow.gpg`,
GitLab does not document a public discovery URL for this key. On self-managed,
your administrator configured it and can export the public half; on
GitLab.com, inspect a web-created commit
(`GET /projects/:id/repository/commits/:sha/signature`) to identify the key
material before enrolling it.

If your history's web commits predate instance signing, they are **unsigned**
— that is the legacy-adoption problem, and the
[adoption boundary](adopt-legacy-github.md#1-the-adoption-decision) is its
honest remedy.

Contributor keys are platform-served, as on GitHub: **⚠ verify on your
instance** — `https://gitlab.com/<user>.keys` serves SSH keys; confirm the
`.gpg` counterpart on your instance version for GPG archaeology.

## Merge discipline

The reason this project merges locally (spec repository ADR-023) applies
identically on GitLab: a platform-created merge is signed by the platform,
not by an accountable human. Keep merge requests, skip the merge button. The
git core of [`scripts/merge-pr.sh`](../../scripts/merge-pr.sh) — signed
`--no-ff` merge, trailer, self-verify, push — is platform-neutral; replace
its `gh pr view/checks` preamble with `glab mr show`/`glab ci status` or the
MR API (**⚠ untested sketch** — this project has not run `glab` in anger).

Set the project's merge method to **merge commit** and disable squash-on-merge
(a platform squash re-authors commits and would be platform-signed).

## Enforcement

The two-ruleset model ports conceptually, not mechanically — GitLab has no
importable ruleset JSON, so there is no `check-rulesets.py` equivalent
(**⚠ open**: a drift check could be rebuilt against the protected-branches
and push-rules APIs):

| This repo's rule (GitHub) | GitLab setting |
|---|---|
| No force-push, no deletion on `main` (no bypass) | Protected branches: allowed-to-push **No one**, allowed-to-merge Maintainers, force-push off |
| `required_signatures` | Push rule **"Reject unsigned commits"** — **Premium/Ultimate tier**; note commits created through the GitLab UI/API are exempt by default |
| PR required + status checks | MR required + "Pipelines must succeed" |
| Admin-role bypass for local merges | Maintainer role in allowed-to-push for the merge push |

On the Free tier the signature rule has no server-side equivalent —
verification still catches unsigned commits after the fact (that is the real
gate), but nothing stops them entering a branch. Weigh that honestly against
your threat model.

## CI

The composite action's logic — build the CLI, run `verify --json`, derive a
badge, honesty contract (abort renders as *unverifiable*, never as a pass) —
is a short shell script wrapped in GitHub Actions syntax; the wrapping is the
only GitHub part. A minimal `.gitlab-ci.yml` job (**⚠ untested** — adapt,
don't paste blindly):

```yaml
semver-trust-verify:
  image: golang:1.26
  script:
    - git fetch origin 'refs/attestations/*:refs/attestations/*'
    - go run github.com/semver-trust/semver-trust-go/cmd/semver-trust@latest
        verify --repo . --from '' --to "$CI_COMMIT_SHA"
        --verify-time "$VERIFY_TIME" --json > verify-report.json
  artifacts:
    paths: [verify-report.json]
  allow_failure: true   # informational-first, as on GitHub; flip when ready
```

For the release pipeline, GitLab's commit-signature API
(`GET /projects/:id/repository/commits/:sha/signature`) is the hygiene-check
substitute — note it returns a `verification_status` string
(`verified`/`unverified`), not GitHub's `verification.verified` boolean, and
the response shape differs per `signature_type` (PGP/SSH/X509).

## Release publishing

GoReleaser supports GitLab releases natively: set the `gitlab:` block in the
`release:` section (plus `gitlab_urls:` for self-managed), provide a
`GITLAB_TOKEN` with `api` scope, and note GitLab v12.9+ is required and
hosted GitLab caps release *attachments* at 10 MB — use the Generic Package
Registry (`use_package_registry: true`) for real binaries. **⚠ verify on your
instance**: cosign *keyless* signing needs an OIDC token; GitLab CI provides
`id_tokens:` with configurable audience — confirm your GitLab version's
sigstore/Fulcio compatibility, or fall back to a self-managed cosign key.
The badge job ports as a plain "commit a JSON file to a branch" script, or
feed GitLab's own badge system from the pipeline.

## Open-questions register

The contract of this guide: every unverified claim above appears here, with
the check you can run. Nothing GitLab-specific outside this table is guessed.

| # | Question | Why it matters | How to verify on your instance | Status |
|---|---|---|---|---|
| 1 | Does `refs/attestations/*` push/fetch/advertise? | Attestation transport | The 3-line smoke test in §what-works-unchanged | ⚠ expected yes; test |
| 2 | Your instance web-signing key + its UID email | Keyring enrollment + `bot_accounts` value | Inspect a web commit via the signature API; ask your admin (self-managed) | ⚠ per-instance |
| 3 | Are your historical web commits signed at all? | Boundary-vs-archaeology decision | Signature API on old web merges; signing GA'd self-managed 17.0 / gitlab.com 18.10 | ⚠ per-history |
| 4 | `https://gitlab.com/<user>.gpg` availability | Contributor key archaeology | Fetch one; `.keys` (SSH) is served | ⚠ confirm |
| 5 | `glab`-based merge script preamble | Local merge flow ergonomics | Port `merge-pr.sh`, run against a scratch MR | ⚠ untested sketch |
| 6 | `.gitlab-ci.yml` verify job as written | CI gate | Run it; adjust image/caching | ⚠ untested sketch |
| 7 | Cosign keyless via GitLab `id_tokens` | Release signing parity | Sign a scratch blob in CI; check Fulcio acceptance | ⚠ confirm |

Verified (no flag): web-UI commits **including merge operations** are signed
by an instance-wide key with committer `GitLab <noreply@gitlab.com>`; the
commit-signature API endpoint and its response shape; push rules ("Reject
unsigned commits") are Premium/Ultimate with UI/API-created commits exempt;
GoReleaser GitLab mode requirements and the 10 MB attachment limit; GitLab
denies pushes only to its own hidden ref namespaces.

If you run this guide against a real GitLab project, the register above is
exactly the feedback this project wants —
[open an issue](https://github.com/semver-trust/semver-trust-go/issues) with
what you measured.
