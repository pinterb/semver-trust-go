#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build-fixtures.sh — construct the internal/vcs tag-enumeration test fixtures.
#
# AGENTS.md / ADR-016: fixture repositories are built by scripts, never
# committed as opaque .git blobs. The go-semver donor tests cloned live GitHub
# repositories at runtime (audit §5.8, a hermeticity violation); this rebuilds
# the same tag set locally with no network access.
#
# Usage: build-fixtures.sh <target-dir>
#
# Creates two repositories under <target-dir>:
#   no-tags/  a repository with one commit and no tags.
#   tagged/   a repository carrying the donor's six-tag set, as a mix of
#             lightweight and annotated tags to prove both enumerate. Note that
#             0.1.0-alpha.01 is deliberately invalid SemVer (leading zero) — it
#             exercises the ParseTags rejected-count path.
set -euo pipefail

dest="${1:?usage: build-fixtures.sh <target-dir>}"

# Identity and signing are set per-invocation so the script runs anywhere,
# independent of the caller's git config (which in this repo signs commits).
git_cmd() {
	git \
		-c init.defaultBranch=main \
		-c user.name='SemVer-Trust Fixture' \
		-c user.email='fixtures@semver-trust.test' \
		-c commit.gpgsign=false \
		-c tag.gpgsign=false \
		"$@"
}

build_repo() {
	repo="$1"
	mkdir -p "$repo"
	git_cmd -C "$repo" init --quiet
	git_cmd -C "$repo" commit --quiet --allow-empty -m 'root commit'
}

# (a) A repository with no tags.
build_repo "${dest}/no-tags"

# (b) A repository with the donor's six-tag set. Lightweight and annotated are
# interleaved; enumeration order is go-git's lexicographic refname order, not
# creation order, so the split here does not affect the expected output.
tagged="${dest}/tagged"
build_repo "$tagged"

# Lightweight tags.
git_cmd -C "$tagged" tag '0.0.2'
git_cmd -C "$tagged" tag '0.1.0-alpha.0.beta'
git_cmd -C "$tagged" tag 'v0.0.1'

# Annotated tags.
git_cmd -C "$tagged" tag -a '0.1.0-alpha.01' -m 'annotated 0.1.0-alpha.01'
git_cmd -C "$tagged" tag -a '0.1.1-beta.0' -m 'annotated 0.1.1-beta.0'
git_cmd -C "$tagged" tag -a 'v0.1.0' -m 'annotated v0.1.0'
