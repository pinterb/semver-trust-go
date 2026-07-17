#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""sync-conformance.py — refresh the vendored conformance artifacts (ADR-021).

Fetches the spec repository's conformance vectors at an exact commit, writes
them under ``conformance/vendor/``, and records the pin — source commit plus a
SHA-256 per file — in ``conformance/manifest.json``, the single place this
implementation pins its spec version. CI verifies the vendored bytes against
the manifest (``go test ./conformance/...``); this script is the only
sanctioned way to change them.

    python3 scripts/sync-conformance.py <spec-commit-sha>

Network access is deliberate and explicit here — the sync task is the one
place refreshing happens (ADR-021); tests and verification never fetch.
Requires Python 3.11+, stdlib only.
"""

import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

REPO_URL = "https://github.com/semver-trust/spec"
RAW_BASE = "https://raw.githubusercontent.com/semver-trust/spec"
FILES = (
    "levels.json",
    "precedence.json",
    "aggregation.json",
    "propagation.json",
    "decision.json",
    "review-qualification.json",
    "range.json",
    "policy-transition.json",
    "version-ancestry.json",
    "source-evidence.json",
    "publishing-profile.json",
    "version-state-canonicalization.json",
    # release/v0.2 + review/v0.2 predicate instances (ADR-030): the vector
    # index plus the payload files it validates against the vendored v0.2
    # schemas (§8.1). Payloads carry no vectors array, so manifest_test skips
    # them in its spec_version cross-check.
    "predicate-v0.2.json",
    "predicate-v0.2/release-valid.json",
    "predicate-v0.2/release-valid-source-evidence-extension.json",
    "predicate-v0.2/release-missing-authority-identity.json",
    "predicate-v0.2/review-valid.json",
    "predicate-v0.2/review-missing-effective-at-merge.json",
    "LICENSE",
    # Cryptographic fixture material (docs/conformance-crypto-fixtures.md):
    # the injected registry, the deterministic fixture-repo builder, the
    # signature vectors, and the vendored test keys they reference.
    "crypto/allowed_signers",
    "crypto/build-fixture-repos.sh",
    "crypto/signature-vectors.json",
    "crypto/keys/human-alice",
    "crypto/keys/human-alice.pub",
    "crypto/keys/human-bob",
    "crypto/keys/human-bob.pub",
    "crypto/keys/agent-ci-bot",
    "crypto/keys/agent-ci-bot.pub",
    "crypto/keys/unknown-mallory",
    "crypto/keys/unknown-mallory.pub",
    "crypto/keys/revoked-carol",
    "crypto/keys/revoked-carol.pub",
    # DSSE attestation fixtures (fixture plan §6): the attestation-signer
    # registry, vectors, and the vendored frozen envelopes.
    "crypto/attestations/allowed_signers",
    "crypto/attestations/attestation-vectors.json",
    "crypto/attestations/envelopes/review-valid.dsse.json",
    "crypto/attestations/envelopes/release-valid.dsse.json",
    "crypto/attestations/envelopes/release-schema-invalid.dsse.json",
    "crypto/attestations/envelopes/release-sig-invalid.dsse.json",
    "crypto/attestations/envelopes/release-unknown-signer.dsse.json",
    # v0.2 successor-predicate positive envelopes (ADR-030): the attestation
    # vectors reference these from draft v0.6 onward.
    "crypto/attestations/envelopes/release-v02-valid.dsse.json",
    "crypto/attestations/envelopes/review-v02-valid.dsse.json",
    # Predicate JSON Schemas (GO-010; live under schemas/, not conformance/).
    "schemas/release-v0.1.json",
    "schemas/review-v0.1.json",
    "schemas/release-v0.2.json",
    "schemas/review-v0.2.json",
)

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "conformance" / "vendor"
MANIFEST = ROOT / "conformance" / "manifest.json"


def fetch(commit: str, name: str) -> bytes:
    # schemas/ entries are repo-root-relative; everything else lives under
    # conformance/.
    prefix = "" if name.startswith("schemas/") else "conformance/"
    url = f"{RAW_BASE}/{commit}/{prefix}{name}"
    with urllib.request.urlopen(url) as resp:
        return resp.read()


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"[0-9a-f]{40}", sys.argv[1]):
        print("usage: sync-conformance.py <full 40-char spec commit sha>", file=sys.stderr)
        return 2
    commit = sys.argv[1]

    VENDOR.mkdir(parents=True, exist_ok=True)
    digests: dict[str, str] = {}
    spec_version = None
    for name in FILES:
        data = fetch(commit, name)
        target = VENDOR / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        digests[name] = "sha256:" + hashlib.sha256(data).hexdigest()
        if name == "levels.json":
            spec_version = json.loads(data)["spec_version"]
        print(f"  {digests[name]}  {name}")

    manifest = {
        "$comment": "SPDX-License-Identifier: Apache-2.0",
        "spec_version": spec_version,
        "source": {"repository": REPO_URL, "commit": commit},
        "files": digests,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"pinned spec draft v{spec_version} at {REPO_URL}@{commit[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
