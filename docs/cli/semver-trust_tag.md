## semver-trust tag

Create an annotated tag at HEAD: the given name or the computed next version

### Synopsis

tag creates an annotated tag at HEAD (zero configuration; unsigned — signed
release tags are the release command's job). With a name argument the
tag is created verbatim after validation: §7.1-valid tags and the lenient
plain forms the donor accepted are allowed; malformed trust shapes and other
invalid names are refused (§7.1 fails closed). Without a name the next
version is computed exactly like `next` and written in canonical §7.1 form
(v-prefixed). The tagger comes from git config unless overridden.

```
semver-trust tag [name] [flags]
```

### Options

```
  -d, --default string[="0.0.0"]     seed version to add as a candidate when set (bare -d seeds 0.0.0)
  -h, --help                         help for tag
  -i, --increment string[="patch"]   increment level: major, minor, patch, premajor, preminor, prepatch, or prerelease (use -i=level) (default "patch")
  -m, --message string               annotation message (default: the tag name)
      --preid string                 identifier prefixing premajor, preminor, prepatch, or prerelease increments
      --repo string                  repository to tag (default ".")
      --tagger-email string          tagger email (default: git config user.email)
      --tagger-name string           tagger name (default: git config user.name)
```

### SEE ALSO

* [semver-trust](semver-trust.md)	 - Provenance-scoped trust levels for semantic versioning

