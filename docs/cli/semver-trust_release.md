## semver-trust release

Evaluate, decide, and emit a release: signed tag + release attestation (spec §10 steps 8-9)

### Synopsis

release runs the complete §10 verification algorithm. Steps 1-7 are exactly
what verify runs — and ANY abort there refuses the release, including a policy
file that fails the §5.4 meta-path level: the configuration is the root of
trust, so a policy whose own history cannot be trusted decides nothing.

Step 8 decides: the semantic floor (§6.1, differ-derived when the policy
configures one and FROM resolves, declared intent otherwise) is honored
unconditionally; the §6.4 decision table maps effective trust × blast to the
clean or pre-release channel, degrading honestly where a required differ
proof is unavailable.

Step 9 emits: an SSH-signed annotated tag (SSHSIG in git's own signature
namespace, so 'git tag -v' verifies it against an allowed-signers file) and a
release attestation — an in-toto Statement under the frozen predicate type,
schema-validated against release-v0.1.json BEFORE signing, signed per ADR-022,
self-verified before output, and stored under refs/attestations/... for both
the release commit and the tag name.

The blast-radius score is operator-supplied in v1 (--blast) and recorded as
such in the attestation's evidence.blast_radius.inputs: the spec's §6.2
mapping is deliberately non-numeric, and an honest "the operator judged this
low" beats a fabricated formula (§1.1). --dry-run evaluates and decides, then
prints the would-be tag and attestation without writing anything.

```
semver-trust release [flags]
```

### Options

```
      --allowed-signers string       filesystem allowed-signers override; empty resolves the policy's identity.human.allowed_signers from TO's tree
      --attest-key string            OpenSSH private key signing the release attestation (attestation namespace; may equal --tag-key)
      --attestation-signers string   filesystem attestation-signer registry; overrides the policy. Empty resolves [identity] attestation_signers from TO's tree (§9); if the policy declares none either, reviews cannot be verified and classify none
      --blast string                 operator-supplied §6.2 blast-radius score: low|moderate|high (required; recorded as operator-supplied in the attestation)
      --claimed-bump string          the bump this release claims: patch|minor|major (required)
      --component string             component to release (tag prefix and attestation component); empty = the single/root component
      --dry-run                      evaluate and decide, print the would-be tag and attestation, write nothing
      --from string                  previous release tag; empty = first release (root..TO, or boundary..TO under a policy-declared adoption_boundary, ADR-024)
      --gpg-keyring string           armored OpenPGP public keyring for GPG-signed commits; overrides the policy. Empty resolves [identity.human] gpg_keyring from TO's tree (§9); if the policy declares none either, the GPG key family is unverifiable and fails closed
  -h, --help                         help for release
      --iteration uint               trust-suffix iteration for a pre-release cut (§7.2 re-cuts increment it) (default 1)
      --json                         emit a structured JSON result instead of the human summary
      --policy string                policy file path within TO's tree (default ".semver-trust/policy.toml")
      --repo string                  repository to release from (default ".")
      --tag-key string               OpenSSH private key signing the tag (git namespace)
      --tagger-email string          tagger email; empty resolves git config user.email
      --tagger-name string           tagger name; empty resolves git config user.name
      --to string                    proposed release commit (revision) (default "HEAD")
      --verify-time string           verification instant (RFC3339); empty = now at the CLI boundary
```

### SEE ALSO

* [semver-trust](semver-trust.md)	 - Provenance-scoped trust levels for semantic versioning

