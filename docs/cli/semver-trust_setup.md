## semver-trust setup

Configure this clone's git for semver-trust (repo-local config only)

### Synopsis

setup writes only this clone's repo-local git configuration — gpg.format,
user.signingkey, commit.gpgsign, commit.template (if .gitmessage exists),
gpg.ssh.allowedSignersFile (SSH mode), and an attestation fetch refspec — through the
git binary (ADR-042). It never writes --global, the working tree, a push refspec, or
a hook: the committed .githooks/commit-msg plus a one-time 'git config core.hooksPath
.githooks' do the hook job without the trust tool writing executable code.

It is all-or-nothing (ADR-039): any key already set to a different value fails the run
listing every conflict, writing nothing. --force overwrites, except user.signingkey,
which is never overwritten by a flag. --dry-run changes nothing and prints the exact
git config commands. Every run ends by printing the commands that reverse it.

```
semver-trust setup [flags]
```

### Options

```
      --dry-run                  print the git config commands; change nothing
      --force                    overwrite conflicting config (never user.signingkey)
      --gpg-signing-key string   a GPG key id to sign commits with
  -h, --help                     help for setup
      --policy string            policy file path within the repository (default ".semver-trust/policy.toml")
      --remote string            remote to configure the attestation fetch refspec on (default "origin")
      --repo string              repository to configure (default ".")
      --signing-key string       path to an SSH public key to sign commits with
```

### SEE ALSO

* [semver-trust](semver-trust.md)	 - Provenance-scoped trust levels for semantic versioning
