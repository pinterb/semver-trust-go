#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build-fixture-repos.sh — construct the SSH signature-verification fixture
# repositories (docs/conformance-crypto-fixtures.md §5, GO-031).
#
# Fixture repositories are built by deterministic scripts at test time, never
# committed as opaque .git blobs. Every input a commit SHA depends on is
# pinned — author/committer identities and dates (the fixture epoch), the
# sha1 object format, messages, trailers, and Ed25519 signatures (RFC 8032
# signing is deterministic) — so the built history is byte-identical across
# runs and machines, and signature-vectors.json can assert exact SHAs as a
# recipe-drift tripwire.
#
# Usage: build-fixture-repos.sh <target-dir>
#
# Repositories created under <target-dir>:
#   signed-history/  alice, ci-bot, and bob commits, each SSH-signed by its
#                    enrolled key: the happy verification paths.
#   unknown-signer/  a commit signed by unknown-mallory, absent from every
#                    allowed-signers file: abort (unverifiable != T0, §5.2).
#   revoked-signer/  a commit signed by revoked-carol, enrolled but invalid
#                    at the fixture epoch: abort, distinct from unknown.
#   gpg-signed/      a commit carrying a PGP-armored signature: the
#                    fail-closed key-family rider (fixture plan §2.1) — a
#                    verifier that cannot verify a key family must treat the
#                    commit as unverifiable, never skip it.
#   tampered/        a commit whose message was altered after signing: the
#                    signature is structurally valid but does not verify.
#
# Each commit is tagged role/<label>; signature-vectors.json references both
# the role tags and the pinned SHAs (dual assertion, fixture plan §5).
set -euo pipefail

dest="${1:?usage: build-fixture-repos.sh <target-dir>}"
keysrc="$(cd "$(dirname "${BASH_SOURCE[0]}")/keys" && pwd)"

# ssh-keygen -Y sign refuses private keys readable by others, and vendored
# copies land with ordinary file modes — so signing uses a private staging
# copy, never the vendored tree (whose bytes are digest-pinned).
keys="$(mktemp -d "${TMPDIR:-/tmp}/semver-trust-fixture-keys.XXXXXX")"
trap 'rm -rf "$keys"' EXIT
cp "${keysrc}"/* "$keys/"
find "$keys" -type f ! -name '*.pub' -exec chmod 600 {} +

# The fixture epoch (docs/conformance-crypto-fixtures.md §3).
epoch='2026-01-01T00:00:00 +0000'
epoch_unix='1767225600'
export GIT_AUTHOR_DATE="$epoch" GIT_COMMITTER_DATE="$epoch"

# commit_signed <repo> <identity> <key-file> <file> <content> <message> <role>
# Configuration is pinned per-invocation so the caller's git config never
# leaks in.
commit_signed() {
	repo="$1" identity="$2" key="$3" file="$4" content="$5" message="$6" role="$7"
	printf '%s\n' "$content" >"${repo}/${file}"
	git -C "$repo" add "$file"
	git \
		-c user.name="${identity%%@*}" \
		-c user.email="$identity" \
		-c gpg.format=ssh \
		-c user.signingkey="${keys}/${key}" \
		-c commit.gpgsign=true \
		-C "$repo" commit --quiet -m "$message"
	git -C "$repo" tag "role/${role}"
}

new_repo() {
	repo="$1"
	mkdir -p "$repo"
	git -c init.defaultBranch=main -C "$repo" init --quiet --object-format=sha1
}

# (a) signed-history: the happy paths.
repo="${dest}/signed-history"
new_repo "$repo"
commit_signed "$repo" 'alice@semver-trust.test' 'human-alice' 'a.txt' 'alice content' 'feat: alice change

Provenance: human' 'alice-commit'
commit_signed "$repo" 'ci-bot@semver-trust.test' 'agent-ci-bot' 'b.txt' 'bot content' 'feat: ci-bot change

Provenance: agent
Provenance-Agent: fixture-agent/1.0' 'ci-bot-commit'
commit_signed "$repo" 'bob@semver-trust.test' 'human-bob' 'c.txt' 'bob content' 'feat: bob change

Provenance: human' 'bob-commit'

# (b) unknown-signer: mallory is absent from every allowed-signers file.
repo="${dest}/unknown-signer"
new_repo "$repo"
commit_signed "$repo" 'alice@semver-trust.test' 'human-alice' 'a.txt' 'alice content' 'feat: alice change

Provenance: human' 'alice-commit'
commit_signed "$repo" 'mallory@semver-trust.test' 'unknown-mallory' 'm.txt' 'mallory content' 'feat: mallory change

Provenance: human' 'mallory-commit'

# (c) revoked-signer: carol is enrolled with valid-before preceding the epoch.
repo="${dest}/revoked-signer"
new_repo "$repo"
commit_signed "$repo" 'carol@semver-trust.test' 'revoked-carol' 'c.txt' 'carol content' 'feat: carol change

Provenance: human' 'carol-commit'

# (d) gpg-signed: a raw commit object carrying a static PGP-armored gpgsig
# header (no real GPG involved — the verifier must abort on the unsupported
# key family before any cryptography happens). Assembled by hand so the
# fixture is deterministic and needs no gpg binary.
repo="${dest}/gpg-signed"
new_repo "$repo"
commit_signed "$repo" 'alice@semver-trust.test' 'human-alice' 'a.txt' 'alice content' 'feat: alice change

Provenance: human' 'alice-commit'
parent="$(git -C "$repo" rev-parse HEAD)"
tree="$(git -C "$repo" rev-parse 'HEAD^{tree}')"
gpg_commit="$(git -C "$repo" hash-object -w -t commit --literally --stdin <<EOF
tree ${tree}
parent ${parent}
author gpg-signer <gpg-signer@semver-trust.test> ${epoch_unix} +0000
committer gpg-signer <gpg-signer@semver-trust.test> ${epoch_unix} +0000
gpgsig -----BEGIN PGP SIGNATURE-----

 iQEzBAABCAAdFiEEc2VtdmVyLXRydXN0IGZpeHR1cmUgc2lnAAoJEAAAAAAAAAAA
 AAAIAJc2VtdmVyLXRydXN0LWNvbmZvcm1hbmNlIFRFU1QgU0lHTkFUVVJFIC0gbm
 90IGEgcmVhbCBQR1Agc2lnbmF0dXJlOyB0aGUgdmVyaWZpZXIgbXVzdCBmYWlsIG
 Nsb3NlZCBvbiB0aGUgdW5zdXBwb3J0ZWQga2V5IGZhbWlseSBiZWZvcmUgcmVhZG
 luZyBpdC4AAAA=
 =TEST
 -----END PGP SIGNATURE-----

feat: gpg-signed change

Provenance: human
EOF
)"
git -C "$repo" update-ref refs/heads/main "$gpg_commit"
git -C "$repo" tag 'role/gpg-commit' "$gpg_commit"

# (e) release: the dedicated release-attestation fixture (fixture plan §6).
# Everything the release-valid payload claims is reproducible from this tree:
# .semver-trust/policy.toml is pinned in the setup commit (outside the
# release range, so its authoring level cannot trip §5.4 inside it), v0.1.0
# tags the setup commit, the range v0.1.0..HEAD holds one human and one
# agent fix: commit (declared intent PATCH → semantic floor patch, §6.1),
# own trust floors to T0, and the demoted release tag v0.1.1-t0.1 points at
# HEAD (§7.1, §8.1: the subject binds the tag name to its commit).
repo="${dest}/release"
new_repo "$repo"
mkdir -p "${repo}/.semver-trust"
cat >"${repo}/.semver-trust/policy.toml" <<'EOF'
# semver-trust-conformance TEST POLICY - fixture-local (crypto fixture plan §6)
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T3"
EOF
git -C "$repo" add .semver-trust/policy.toml
printf 'v1\n' >"${repo}/app.txt"
git -C "$repo" add app.txt
git \
	-c user.name='alice' \
	-c user.email='alice@semver-trust.test' \
	-c gpg.format=ssh \
	-c user.signingkey="${keys}/human-alice" \
	-c commit.gpgsign=true \
	-C "$repo" commit --quiet -m 'feat: initial release

Provenance: human'
git -C "$repo" tag 'v0.1.0'
git -C "$repo" tag 'role/release-setup-commit'
commit_signed "$repo" 'alice@semver-trust.test' 'human-alice' 'app.txt' 'v1 fixed' 'fix: correct output

Provenance: human' 'release-alice-commit'
commit_signed "$repo" 'ci-bot@semver-trust.test' 'agent-ci-bot' 'app.txt' 'v1 fixed again' 'fix: correct output again

Provenance: agent
Provenance-Agent: fixture-agent/1.0' 'release-ci-bot-commit'
git -C "$repo" tag 'v0.1.1-t0.1'

# (f) tampered: alice's signed commit object, message altered after signing;
# the original sshsig no longer covers the bytes.
repo="${dest}/tampered"
new_repo "$repo"
commit_signed "$repo" 'alice@semver-trust.test' 'human-alice' 'a.txt' 'alice content' 'feat: alice change

Provenance: human' 'alice-commit'
tampered="$(git -C "$repo" cat-file commit HEAD | sed 's/^feat: alice change$/feat: tampered change/' |
	git -C "$repo" hash-object -w -t commit --literally --stdin)"
git -C "$repo" update-ref refs/heads/main "$tampered"
git -C "$repo" tag 'role/tampered-commit' "$tampered"
