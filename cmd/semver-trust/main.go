// SPDX-License-Identifier: Apache-2.0

// Command semver-trust is the SemVer-Trust CLI. The root surfaces the tool
// version and the vendored conformance pin (ADR-021 — the manifest is the
// single spec-version-pin location); `verify` (GO-040) walks a release range
// and reports its provenance and trust per spec §10 steps 1–7. The `release`
// and `policy` commands arrive with GO-041/042.
//
// The framework is cobra (maintainer decision 2026-07-11, resolving the
// implementation-plan §5 [P] taste call). cmd/ stays a thin adapter: it parses
// flags, reads the wall clock once at the process boundary (the only sanctioned
// time.Now — ADR-018 keeps internal/* clock-free by injecting it), and renders
// what internal/verify returns.
package main

import (
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		// cobra has already written the error to stderr (SilenceErrors is off);
		// an abort names the §10 step it failed at. Exit non-zero.
		os.Exit(1)
	}
}
