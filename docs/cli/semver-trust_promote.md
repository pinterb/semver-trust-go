## semver-trust promote

Promote a pre-release to the clean channel on the identical SHA (spec §7.3, ADR-009)

### Synopsis

promote re-runs the §10 decision at an existing pre-release tag's own commit
with the evidence that has accumulated since it was cut, and — if the release
now qualifies for the clean channel — creates the clean tag on the IDENTICAL
SHA and publishes a superseding release attestation (§7.3, §10 step 10).

The source never changes. --tag names an existing pre-release trust version
(e.g. v1.4.0-t0.3); promote resolves it to its commit, loads the policy from
that tree, and locates the prior release attestation stored under the tag. The
claimed bump and blast score are NOT restated — they describe the same change
set and are carried from the prior attestation; only the evidence, re-read from
the current attestation store, moves. (--blast may override the carried score
when a fresh blast assessment is warranted.)

Promotion is not re-cutting. If the re-evaluation still lands in the
pre-release channel, promote refuses outright — cutting a new pre-release
iteration is release's job (§7.2), not promotion's. If it qualifies clean, the
clean tag is created on the same SHA (refused if it already exists) and the new
attestation's supersedes points at the prior envelope's stable ref (§8.1),
storing under both the new tag and the commit. --dry-run evaluates, decides,
and prints the would-be promotion without writing anything.

```
semver-trust promote [flags]
```

### Options

```
      --allowed-signers string       filesystem allowed-signers override; empty resolves the policy's identity.human.allowed_signers from the tag's tree
      --attest-key string            OpenSSH private key signing the release attestation (attestation namespace; may equal --tag-key)
      --attestation-signers string   filesystem attestation-signer registry; overrides the policy. Empty resolves [identity] attestation_signers from the tag's tree (§9); if the policy declares none either, reviews cannot be verified and classify none
      --blast string                 override the §6.2 blast-radius score (low|moderate|high); empty carries the prior attestation's score
      --component string             component to promote (tag prefix and attestation component); empty = the single/root component
      --dry-run                      evaluate and decide, print the would-be promotion, write nothing
      --gpg-keyring string           armored OpenPGP public keyring for GPG-signed commits; overrides the policy. Empty resolves [identity.human] gpg_keyring from the tag's tree (§9); if the policy declares none either, the GPG key family is unverifiable and fails closed
  -h, --help                         help for promote
      --json                         emit a structured JSON result instead of the human summary
      --policy string                policy file path within the tag's tree (default ".semver-trust/policy.toml")
      --repo string                  repository to promote in (default ".")
      --tag string                   existing pre-release trust tag to promote (required; must parse as a §7.1 trust version)
      --tag-key string               OpenSSH private key signing the clean tag (git namespace)
      --tagger-email string          tagger email; empty resolves git config user.email
      --tagger-name string           tagger name; empty resolves git config user.name
      --verify-time string           verification instant (RFC3339); empty = now at the CLI boundary
```

### SEE ALSO

* [semver-trust](semver-trust.md)	 - Provenance-scoped trust levels for semantic versioning

