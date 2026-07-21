## semver-trust doctor

Diagnose this environment before verification (read-only)

### Synopsis

doctor runs read-only checks that surface, at authoring time, the mistakes
verification would later abort or mis-price — an unenrolled signing key, a
malformed registry, a missing trailer, a policy that will not parse — each with
the exact fix. It writes nothing and ends by printing the verify invocation it
preempts.

Persona (maintainer/contributor/agent) selects the check-set and is auto-detected
for humans (a principal enrolled in attestation_signers is a maintainer); pass
--persona to override. --persona agent is the one mode an agent is sanctioned to
run and restricts the run to a side-effect-free subset.

```
semver-trust doctor [flags]
```

### Options

```
      --at string                     diagnosis instant (RFC3339); empty = now at the CLI boundary
      --bootstrap-descriptor string   out-of-band bootstrap descriptor (enables chain/chain-head)
      --commit string                 diagnose a specific commit revision
  -h, --help                          help for doctor
      --json                          emit a structured JSON report instead of the human table
      --message string                diagnose a commit-message file (- for stdin)
      --persona string                maintainer|contributor|agent (default: auto-detected for humans)
      --policy string                 policy file path within the repository (default ".semver-trust/policy.toml")
      --repo string                   repository to diagnose (default ".")
      --staged                        diagnose the staged changes (simulate checks)
      --strict                        promote WARN to FAIL
```

### SEE ALSO

* [semver-trust](semver-trust.md)	 - Provenance-scoped trust levels for semantic versioning
