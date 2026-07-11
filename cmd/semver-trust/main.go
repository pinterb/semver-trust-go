// SPDX-License-Identifier: Apache-2.0

// Command semver-trust is the SemVer-Trust CLI. This is the GO-026 skeleton:
// it surfaces the tool version and the vendored conformance pin (ADR-021 —
// the manifest is the single spec-version-pin location, surfaced here). The
// verify, release, and policy commands arrive with Phase 4 (GO-040..042);
// the CLI framework choice (cobra vs stdlib flag, implementation plan §5) is
// a maintainer decision this skeleton deliberately does not foreclose.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/semver-trust/semver-trust-go/conformance"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and conformance pin")
	flag.Usage = usage
	flag.Parse()

	if *showVersion || (flag.NArg() == 1 && flag.Arg(0) == "version") {
		fmt.Println(versionString())
		return
	}
	usage()
	os.Exit(2)
}

func versionString() string {
	toolVersion := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		toolVersion = info.Main.Version
	}
	return fmt.Sprintf(
		"semver-trust %s\nconformance: SemVer-Trust spec draft v%s vectors (%s@%.12s)",
		toolVersion,
		conformance.SpecVersion(),
		"github.com/semver-trust/spec",
		conformance.SourceCommit(),
	)
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: semver-trust [--version | version]

The verify, release, and policy commands arrive with the Phase 4 work
(GO-040..042); this build surfaces only the version and conformance pin.
`)
	flag.PrintDefaults()
}
