<!-- SPDX-License-Identifier: Apache-2.0 -->
# Branch rulesets — settings as reviewable artifacts

These files are the source of truth for the `main` branch's protection,
committed so an outsider can see exactly what governs the branch the
verifiable history lives on. Apply them via *Settings → Rules → Rulesets →
Import a ruleset*; change them by editing the file and re-importing, never by
click-editing alone. `scripts/check-rulesets.py` compares the live settings
against these files and fails on drift.

Two rulesets, split by bypass policy (a bypass actor bypasses *every* rule in
a ruleset, so rules that must bind everyone live apart from rules a
maintainer may bypass):

| File | Rules | Bypass |
|---|---|---|
| `branch-main-history-integrity.json` | no deletion, no force push, signed commits | **nobody** — history integrity is absolute |
| `branch-main-review-gate.json` | PR required (merge commits only), status checks (`ci`, `commit-hygiene`) | Repository role **Admin** (`actor_id: 5`), mode `always` |

The review-gate bypass exists for the ADR-023 local-merge flow: the
maintainer pushes a locally-created, signed, trailered merge commit
(`scripts/merge-pr.sh` refuses to create one unless the PR is open with
green checks, so the process the bypass skips is still enforced by tooling).
The bypass is granted to the Admin *role*, not a named account — what is
committed here is byte-for-byte what is applied, with no personal variation.

Notes:

- `~DEFAULT_BRANCH` targets whatever the default branch is; no hardcoded
  branch names.
- The organization-level tag ruleset is managed at the org and is
  deliberately not represented here.
- "Require linear history" must stay absent: this repository is
  merge-commits-only (spec §4.3.3), the opposite of linear.
- **Migration**: rulesets and classic branch protection can coexist
  (most-restrictive-wins), so import these first, confirm a test push
  behaves, then delete any classic branch protection on `main`. The drift
  check sees rulesets only — classic protection is invisible to it, which
  is one more reason to finish the migration.
- These files are configuration that protects the system; once this
  repository carries its own policy file, `.github/rulesets/**` belongs in
  its §5.4 meta-paths.
