<!-- SPDX-License-Identifier: Apache-2.0 -->
# Development tools module

This directory is a **separate Go module** that pins the project's Go-based
development tools as [`go tool`](https://go.dev/doc/modules/managing-dependencies#tools)
dependencies (Go 1.24+ `tool` directives in `go.mod`). Keeping them here, out of
the root `go.mod`, keeps the shipped module's dependency graph clean while making
tool versions reproducible and reviewable.

## Pinned tools

- `golangci-lint` — Go linter aggregator (`task lint:go`, `task fmt:go`)
- `gotestsum` — test runner with agent-readable output (`task test:go`)
- `govulncheck` — known-vulnerability scanner (`task vuln:go`)

## Usage

These are invoked via the root `Taskfile.yml`, never directly. Under the hood each
call is:

```sh
go tool -modfile=tools/go.mod <tool> [args]
```

The first invocation compiles the tool from source (cached thereafter).

## Maintenance

Add a tool from the repo root:

```sh
go -C tools get -tool <module-path>
```

Keep both modules tidy (root and tools):

```sh
task mod
```
