## semver-trust verify

Verify a release range's provenance and trust (spec §10 steps 1–7)

### Synopsis

verify walks the commit range FROM..TO (root..TO for a first release),
loads the policy from TO's tree, verifies every commit's signature and any
covering review attestation, applies derivation proofs, and aggregates trust
into per-scope own floors and effective trust over the workspace graph.

It fails closed: any commit that cannot be verified end-to-end, or a meta-path
commit below the required level, aborts the run with a one-line reason naming
the spec §10 step that failed (unverifiable is never T0, §5.2; the config
protects the system, §5.4).

A first release (no --from) anchors at the adoption boundary when the policy
declares one ([policy] adoption_boundary, ADR-026): history before the
boundary is exempt and makes no claim, and the report discloses the boundary
in both renderings. The boundary is policy-pinned by design — there is no
flag for it, because a CLI-supplied boundary could be moved by whoever runs
the verifier.

```
semver-trust verify [flags]
```

### Options

```
      --allowed-signers string       filesystem allowed-signers override; empty resolves the policy's identity.human.allowed_signers from TO's tree
      --attestation-signers string   filesystem attestation-signer registry; overrides the policy. Empty resolves [identity] attestation_signers from TO's tree (§9); if the policy declares none either, reviews cannot be verified and classify none
      --component string             workspace component to headline; empty = single/root component
      --from string                  previous release tag; empty = first release (root..TO, or boundary..TO under a policy-declared adoption_boundary, ADR-026)
      --gpg-keyring string           armored OpenPGP public keyring for GPG-signed commits; overrides the policy. Empty resolves [identity.human] gpg_keyring from TO's tree (§9); if the policy declares none either, the GPG key family is unverifiable and fails closed
  -h, --help                         help for verify
      --json                         emit a structured JSON report instead of the human table
      --policy string                policy file path within TO's tree (default ".semver-trust/policy.toml")
      --repo string                  repository to verify (default ".")
      --to string                    proposed release commit (revision) (default "HEAD")
      --verify-time string           verification instant (RFC3339); empty = now at the CLI boundary
```

### SEE ALSO

* [semver-trust](semver-trust.md)	 - Provenance-scoped trust levels for semantic versioning

