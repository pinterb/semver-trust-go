## semver-trust

Provenance-scoped trust levels for semantic versioning

### Synopsis

semver-trust implements the SemVer-Trust scheme: it captures the
provenance of source changes, aggregates it into a trust level, and verifies a
release against a repository policy (spec §10).

Commands: verify — walk a release range and report per-commit provenance and
effective trust; release — decide channel and version and emit the signed tag
plus the release attestation (§10 steps 8-9); promote — re-decide a
pre-release at its own SHA with new evidence and, if it now qualifies, cut the
clean tag on the identical commit with a superseding attestation (§7.3);
attest review — emit a signed §4.3 review attestation over commits; policy
validate/explain and the zero-configuration plain-mode tag commands list,
latest, next, and tag.

### Options

```
  -h, --help   help for semver-trust
```

### SEE ALSO

* [semver-trust attest](semver-trust_attest.md)	 - Emit signed SemVer-Trust attestations
* [semver-trust completion](semver-trust_completion.md)	 - Generate the autocompletion script for the specified shell
* [semver-trust latest](semver-trust_latest.md)	 - Print the highest version among the repository's tags (zero configuration)
* [semver-trust list](semver-trust_list.md)	 - List the repository's tags as versions (zero configuration)
* [semver-trust next](semver-trust_next.md)	 - Print the version that follows the latest tag (zero configuration)
* [semver-trust policy](semver-trust_policy.md)	 - Validate and explain the repository policy (§9)
* [semver-trust promote](semver-trust_promote.md)	 - Promote a pre-release to the clean channel on the identical SHA (spec §7.3, ADR-009)
* [semver-trust release](semver-trust_release.md)	 - Evaluate, decide, and emit a release: signed tag + release attestation (spec §10 steps 8-9)
* [semver-trust tag](semver-trust_tag.md)	 - Create an annotated tag at HEAD: the given name or the computed next version
* [semver-trust verify](semver-trust_verify.md)	 - Verify a release range's provenance and trust (spec §10 steps 1–7)
* [semver-trust version](semver-trust_version.md)	 - Print the tool version and conformance pin

