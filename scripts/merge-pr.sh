#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# merge-pr.sh — merge a pull request locally per ADR-023: a --no-ff merge
# commit, signed by the merger's enrolled key and carrying Provenance
# trailers, pushed to the protected branch by a ruleset-bypass maintainer.
# Web-flow merges (unsigned-by-a-person, untrailered) are not used.
#
# Usage: merge-pr.sh <pr-number> [upstream-repo]
#   e.g. scripts/merge-pr.sh 33
#        scripts/merge-pr.sh 17 semver-trust/spec
#
# Prerequisites (one-time):
#   - commit.gpgsign=true and user.signingkey configured (every commit in
#     these repositories is signed, merges included).
#   - The merger listed as a bypass actor on the branch ruleset's push
#     restriction (PRs and green checks stay required; the bypass only lets
#     the merge commit itself be pushed).
#   - gh authenticated; remotes: origin = your fork, upstream = the
#     canonical repository.
set -euo pipefail

pr="${1:?usage: merge-pr.sh <pr-number> [upstream-repo]}"
repo="${2:-$(git remote get-url upstream | sed -E 's#.*github.com[:/]##; s#\.git$##')}"

title="$(gh pr view "$pr" --repo "$repo" --json title -q .title)"
state="$(gh pr view "$pr" --repo "$repo" --json state -q .state)"
if [ "$state" != "OPEN" ]; then
	echo "PR #${pr} is ${state}, not OPEN" >&2
	exit 1
fi

checks_ok="$(gh pr checks "$pr" --repo "$repo" --json bucket \
	-q 'length > 0 and all(.bucket == "pass" or .bucket == "skipping")')"
if [ "$checks_ok" != "true" ]; then
	echo "PR #${pr} checks are not green:" >&2
	gh pr checks "$pr" --repo "$repo" >&2 || true
	exit 1
fi

git fetch upstream
git checkout main
git merge --ff-only upstream/main
git fetch upstream "pull/${pr}/head"

# Subject mirrors the PR title; the trailer block is the final paragraph.
# The merge is the merger's own act: Provenance: human.
git merge --no-ff FETCH_HEAD \
	-m "${title} (#${pr})" \
	-m "Provenance: human"

# Self-check before publishing: signature present and trailer block intact.
git log -1 --format='%G?|%(trailers:key=Provenance,valueonly)' | grep -qE '^[GU]\|human$' || {
	echo "merge commit failed the signature/trailer self-check; not pushing" >&2
	git reset --hard upstream/main
	exit 1
}

git push upstream main
git push origin main
echo "merged PR #${pr}: $(git log -1 --format='%h %s')"
