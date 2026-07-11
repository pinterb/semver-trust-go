#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""check-rulesets.py — live GitHub rulesets vs the committed artifacts.

The files under .github/rulesets/ are the source of truth for the default
branch's protection; this check compares them against the repository's live
rulesets (via `gh api`) and fails on drift in either direction: a committed
ruleset that is missing or differs live, or a live repository branch ruleset
that no committed file describes.

Comparison rules: name, target, enforcement, conditions, and bypass_actors
must match exactly; each committed rule must exist live with the committed
parameters as a subset (the API decorates rules with server-side defaults,
which are not drift), and no extra live rules may appear. Organization-level
rulesets (the tag ruleset) are out of scope.

    python3 scripts/check-rulesets.py

Requires gh authenticated with read access to the upstream repository's
rulesets. When the API is not accessible (e.g. an unauthenticated CI run),
the check reports SKIP loudly and exits 0 — the authoritative run is the
maintainer's, where `gh` is authenticated; a silent pass is never printed
without the live comparison actually happening.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULESETS = ROOT / ".github" / "rulesets"

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  — ' + detail) if (detail and not ok) else ''}")
    if not ok:
        failures.append(name)


def upstream_repo() -> str:
    url = subprocess.run(
        ["git", "remote", "get-url", "upstream"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return url.split("github.com")[-1].lstrip(":/").removesuffix(".git")


def gh_api(path: str) -> object | None:
    result = subprocess.run(["gh", "api", path], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)


def normalize(doc: dict) -> dict:
    return {
        "target": doc.get("target"),
        "enforcement": doc.get("enforcement"),
        "conditions": doc.get("conditions"),
        "bypass_actors": sorted(
            (
                {
                    "actor_id": a.get("actor_id"),
                    "actor_type": a.get("actor_type"),
                    "bypass_mode": a.get("bypass_mode"),
                }
                for a in doc.get("bypass_actors") or []
            ),
            key=lambda a: (str(a["actor_type"]), str(a["actor_id"])),
        ),
        "rules": {r["type"]: r.get("parameters") or {} for r in doc.get("rules") or []},
    }


def params_subset(committed: object, live: object) -> bool:
    """Committed parameters must appear in the live rule; the API adds
    server-side defaults, which are not drift."""
    if isinstance(committed, dict) and isinstance(live, dict):
        return all(k in live and params_subset(v, live[k]) for k, v in committed.items())
    if isinstance(committed, list) and isinstance(live, list):
        return sorted(map(json.dumps, committed)) == sorted(map(json.dumps, live))
    return committed == live


def compare(name: str, committed: dict, live: dict) -> None:
    for field in ("target", "enforcement", "conditions", "bypass_actors"):
        check(
            f"ruleset-{name}-{field}",
            committed[field] == live[field],
            f"committed {committed[field]!r}, live {live[field]!r}",
        )
    for rule_type, params in committed["rules"].items():
        if rule_type not in live["rules"]:
            check(f"ruleset-{name}-rule-{rule_type}", False, "missing live")
            continue
        check(
            f"ruleset-{name}-rule-{rule_type}",
            params_subset(params, live["rules"][rule_type]),
            f"committed {params!r}, live {live['rules'][rule_type]!r}",
        )
    extra = set(live["rules"]) - set(committed["rules"])
    check(f"ruleset-{name}-no-extra-rules", not extra, f"live-only rules: {sorted(extra)}")


def main() -> int:
    committed = {}
    for path in sorted(RULESETS.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        committed[doc["name"]] = normalize(doc)
    check("rulesets-committed-present", bool(committed))

    repo = upstream_repo()
    listing = gh_api(f"repos/{repo}/rulesets")
    if listing is None:
        print(
            f"SKIP  live comparison: gh api repos/{repo}/rulesets not accessible "
            "(authenticate gh to run the authoritative check)"
        )
        return 0

    live = {}
    for item in listing:
        if item.get("source_type") != "Repository" or item.get("target") != "branch":
            continue
        detail = gh_api(f"repos/{repo}/rulesets/{item['id']}")
        if detail is None:
            check(f"ruleset-fetch-{item.get('name')}", False, "detail fetch failed")
            continue
        live[detail["name"]] = normalize(detail)

    for name in committed:
        if name not in live:
            check(f"ruleset-{name}-exists-live", False, "committed but not applied")
            continue
        compare(name, committed[name], live[name])
    unexpected = set(live) - set(committed)
    check(
        "rulesets-no-unexpected-live",
        not unexpected,
        f"live branch rulesets with no committed artifact: {sorted(unexpected)}",
    )

    print(f"\n{'OK' if not failures else 'RULESET DRIFT'}: {len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
