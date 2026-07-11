#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build-walk-fixtures.sh — construct the internal/vcs range-walk test
# fixtures (GO-030).
#
# AGENTS.md / ADR-016: fixture repositories are built by scripts, never
# committed as opaque .git blobs. No network access.
#
# Usage: build-walk-fixtures.sh <target-dir>
#
# Creates four repositories under <target-dir>:
#   first-release/  linear history with Provenance trailers and a v0.1.0 tag
#                   on the second commit; exercises root..TO and FROM..TO.
#   merged/         a --no-ff merge of disjoint edits (a clean merge): the
#                   merge commit carries no novel content. The
#                   merge-commits-only history the scheme mandates in place
#                   of squash/rebase merging (spec §4.3.3).
#   conflicted/     a merge whose conflict was resolved by hand: the merge
#                   commit's resolution content matches neither parent
#                   (spec §4.3.4).
#   rewritten/      a branch pair where "released" is NOT an ancestor of
#                   "main" (the release commit was amended away): a rewritten
#                   protected branch, which must fail range enumeration
#                   (spec §10.2).
set -euo pipefail

dest="${1:?usage: build-walk-fixtures.sh <target-dir>}"

# Identity, signing, and merge behavior are pinned per-invocation so the
# script runs anywhere, independent of the caller's git config.
git_cmd() {
	git \
		-c init.defaultBranch=main \
		-c user.name='SemVer-Trust Fixture' \
		-c user.email='fixtures@semver-trust.test' \
		-c commit.gpgsign=false \
		-c tag.gpgsign=false \
		-c merge.ff=false \
		"$@"
}

commit_file() {
	repo="$1" file="$2" content="$3" message="$4"
	mkdir -p "$(dirname "${repo}/${file}")"
	printf '%s\n' "$content" >"${repo}/${file}"
	git_cmd -C "$repo" add "$file"
	git_cmd -C "$repo" commit --quiet -m "$message"
}

# (a) first-release: linear, trailered, tagged mid-history.
repo="${dest}/first-release"
mkdir -p "$repo"
git_cmd -C "$repo" init --quiet
commit_file "$repo" 'pkg/common/util.go' 'package common' 'feat: seed common

Provenance: human'
commit_file "$repo" 'services/auth/handler.go' 'package auth' 'feat: auth handler

Provenance: agent
Provenance-Agent: fixture-agent/1.0'
git_cmd -C "$repo" tag v0.1.0
commit_file "$repo" 'docs/auth.md' '# auth' 'docs: auth notes

Provenance: mixed'

# (b) merged: disjoint edits, clean --no-ff merge.
repo="${dest}/merged"
mkdir -p "$repo"
git_cmd -C "$repo" init --quiet
commit_file "$repo" 'a.txt' 'base a' 'feat: base

Provenance: human'
git_cmd -C "$repo" tag base
git_cmd -C "$repo" switch --quiet -c feature
commit_file "$repo" 'b.txt' 'feature b' 'feat: feature side

Provenance: human'
git_cmd -C "$repo" switch --quiet main
commit_file "$repo" 'a.txt' 'main a' 'feat: main side

Provenance: human'
git_cmd -C "$repo" merge --quiet --no-ff feature -m 'merge: feature (clean)

Provenance: human'

# (c) conflicted: both sides edit the same line; resolution matches neither.
repo="${dest}/conflicted"
mkdir -p "$repo"
git_cmd -C "$repo" init --quiet
commit_file "$repo" 'conflict.txt' 'base line' 'feat: base

Provenance: human'
git_cmd -C "$repo" tag base
git_cmd -C "$repo" switch --quiet -c feature
commit_file "$repo" 'conflict.txt' 'feature line' 'feat: feature edit

Provenance: human'
git_cmd -C "$repo" switch --quiet main
commit_file "$repo" 'conflict.txt' 'main line' 'feat: main edit

Provenance: human'
git_cmd -C "$repo" merge --quiet feature -m 'merge: feature (conflict)' || true
printf 'resolved line\n' >"${repo}/conflict.txt"
git_cmd -C "$repo" add conflict.txt
git_cmd -C "$repo" commit --quiet --no-edit -m 'merge: feature (conflict resolved)

Provenance: human'

# (d) rewritten: "released" points at a commit amended out of main's history.
repo="${dest}/rewritten"
mkdir -p "$repo"
git_cmd -C "$repo" init --quiet
commit_file "$repo" 'a.txt' 'v1' 'feat: base

Provenance: human'
commit_file "$repo" 'a.txt' 'v2' 'feat: released work

Provenance: human'
git_cmd -C "$repo" branch released
git_cmd -C "$repo" commit --quiet --amend -m 'feat: released work, rewritten

Provenance: human'
