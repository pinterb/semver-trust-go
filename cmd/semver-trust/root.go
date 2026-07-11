// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/semver-trust/semver-trust-go/conformance"
)

// newRootCmd builds the root command tree. SilenceUsage keeps a runtime abort
// from dumping the full usage text after its one-line reason; errors are left
// unsilenced so cobra prints them (the verify abort message names its §10 step)
// and main maps a returned error to a non-zero exit.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "semver-trust",
		Short: "Provenance-scoped trust levels for semantic versioning",
		Long: `semver-trust implements the SemVer-Trust scheme: it captures the
provenance of source changes, aggregates it into a trust level, and verifies a
release against a repository policy (spec §10).

Available now: verify (GO-040) — walk a release range and report per-commit
provenance and effective trust. Arriving with Phase 4: release (GO-042) and
policy (GO-041).`,
		SilenceUsage: true,
		Version:      versionString(),
	}
	// The version output is a fixed two-line shape (tool version + conformance
	// pin); print it verbatim rather than cobra's "<name> version <v>" default.
	root.SetVersionTemplate("{{.Version}}\n")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newVerifyCmd())
	return root
}

// newVersionCmd mirrors the `--version` flag as a subcommand, printing the
// identical two-line shape.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the tool version and conformance pin",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), versionString())
			return err
		},
	}
}

// versionString is the acceptance surface for the GO-026 pin: the tool version,
// the spec draft version, and the source commit — the latter two from the
// vendored manifest, the single pin location.
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
