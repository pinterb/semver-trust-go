## semver-trust enroll

Generate a trust-material enrollment line (read-only by default)

### Synopsis

enroll formats a key into the byte-exact registry line the human commits, and
prints it — raw registry bytes on stdout, all guidance on stderr. It never stages,
commits, or signs: the tool generates and validates; the human enrolls, commits,
and signs (ADR-038).

The principal defaults from git user.email (the same identity your commits carry),
so the registry principal equals your commit identity by construction. Namespaces
come from compiled constants, so the "git" / attestation namespace can never be
mistyped.

--write appends the line to the working-tree registry named by the policy, under
the atomic writer contract (ADR-039): a repo-relative path fence, no directory
creation, a strict re-parse of the whole result, and a temp-file + fsync + rename.
--dry-run makes zero filesystem changes and prints exactly what --write would do.

```
semver-trust enroll [flags]
```

### Options

```
      --attest-key string   path to an SSH public key to enroll as an attestation signer
      --commit-key string   path to an SSH public key to enroll as a commit signer
      --dry-run             print exactly what --write would do; change nothing
      --email string        principal to enroll (default: git user.email)
  -h, --help                help for enroll
      --policy string       policy file path within the repository (default ".semver-trust/policy.toml")
      --repo string         repository to enroll into (default ".")
      --write               append the line to the working-tree registry (atomic)
```

### SEE ALSO

* [semver-trust](semver-trust.md)	 - Provenance-scoped trust levels for semantic versioning
