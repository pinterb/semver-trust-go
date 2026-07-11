// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/trust"
)

// newPolicyCmd is the `policy` command group (GO-041): validate and explain a
// repository's policy file. Both read the WORKING-TREE file — the release
// pipeline (verify/release) reads the policy from TO's tree instead, so a
// clean `policy validate` here does not by itself prove what a release run
// will load (§10 step 1).
func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Validate and explain the repository policy (§9)",
	}
	cmd.AddCommand(newPolicyValidateCmd())
	cmd.AddCommand(newPolicyExplainCmd())
	return cmd
}

// addPolicyFlags registers the flags the policy subcommands share.
func addPolicyFlags(cmd *cobra.Command, repoPath, policyPath *string) {
	f := cmd.Flags()
	f.StringVar(repoPath, "repo", ".", "repository whose working tree holds the policy")
	f.StringVar(policyPath, "policy", ".semver-trust/policy.toml", "policy file path (relative to --repo unless absolute)")
}

// loadPolicy reads and parses the working-tree policy file. A missing file is
// a clear, honest error: the plain-mode commands need no policy (zero
// configuration), but the policy commands are ABOUT the file, so they cannot
// invent one.
func loadPolicy(repoPath, policyPath string) (*policy.Policy, string, error) {
	path := policyPath
	if !filepath.IsAbs(path) {
		path = filepath.Join(repoPath, policyPath)
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, path, fmt.Errorf(
			"no policy file at %s — plain-mode commands work without one (zero configuration), but the policy commands need the file itself; create it or point --policy at it", path)
	}
	if err != nil {
		return nil, path, err
	}
	p, err := policy.Parse(data)
	if err != nil {
		// The parse error is returned verbatim (§5.4: the config protects the
		// system, so its rejection reasons must reach the operator intact).
		return nil, path, err
	}
	return p, path, nil
}

func newPolicyValidateCmd() *cobra.Command {
	var repoPath, policyPath string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Parse the policy file and print its digest and summary",
		Long: `validate loads the policy from the working tree, runs the strict §9 parser
(unknown keys and out-of-vocabulary values are errors — the config is the root
of trust, §5.4), and prints the digest and a summary. Parse errors are printed
verbatim and exit non-zero.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, path, err := loadPolicy(repoPath, policyPath)
			if err != nil {
				return err
			}
			e := &errWriter{w: cmd.OutOrStdout()}
			e.printf("policy %s is valid (schema %s)\n", path, p.Version)
			e.printf("digest:      sha256:%s\n", p.Digest)
			e.printf("threshold:   %s\n", p.Threshold)
			e.printf("strategy:    %s\n", p.Strategy)
			e.printf("scopes:      %d glob(s), %d weight(s)\n", len(p.Scopes), len(p.Weights))
			e.printf("meta-paths:  %d at required level %s\n", len(p.Meta.Paths), p.Meta.RequiredLevel)
			e.printf("derivations: %d\n", len(p.Derivations))
			e.printf("graph:       %s\n", p.GraphAdapter)
			return e.err
		},
	}
	addPolicyFlags(cmd, &repoPath, &policyPath)
	return cmd
}

func newPolicyExplainCmd() *cobra.Command {
	var repoPath, policyPath string
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Print the decision table in effect (§6.4) and the policy summary",
		Long: `explain renders the release decision machinery the policy configures: the
threshold and §6.3 strategy, the §6.4 default decision table Decide runs
(rows T0-T3 by blast score low/moderate/high), and the scope map, weights,
meta-paths, and derivation rules.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, path, err := loadPolicy(repoPath, policyPath)
			if err != nil {
				return err
			}
			return writeExplain(cmd.OutOrStdout(), p, path)
		},
	}
	addPolicyFlags(cmd, &repoPath, &policyPath)
	return cmd
}

// writeExplain renders the decision table in effect and the policy summary.
func writeExplain(out io.Writer, p *policy.Policy, path string) error {
	e := &errWriter{w: out}
	e.printf("decision table in effect (§6.4 default) — policy %s\n\n", path)
	e.printf("threshold: %s (minimum effective trust for the clean channel)\n", p.Threshold)
	e.printf("strategy:  %s — %s\n\n", p.Strategy, strategyNote(p.Strategy))

	tw := tabwriter.NewWriter(out, 2, 0, 2, ' ', 0)
	et := &errWriter{w: tw}
	et.println("trust\tblast low\tblast moderate\tblast high")
	for _, level := range []trust.Level{trust.T0, trust.T1, trust.T2, trust.T3} {
		row := []string{level.String()}
		for _, blast := range []trust.Blast{trust.BlastLow, trust.BlastModerate, trust.BlastHigh} {
			cell, err := trust.DecisionCell(level, blast)
			if err != nil {
				return err
			}
			row = append(row, cell.String())
		}
		et.println(strings.Join(row, "\t"))
	}
	if et.err != nil {
		return et.err
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	e.printf(`
cells: "clean" releases the plain version on the clean channel; "differ proof
(patch)" needs a compatibility-differ proof for PATCH claims and "differ proof
(any)" for every claim — without one the cell demotes (honest degradation,
§1.1); "pre-release" always demotes. A demoted release %s.
`, demotionNote(p.Strategy))

	e.println()
	if len(p.Scopes) == 0 {
		e.println("scopes:      none declared (every path is the implicit \"default\" scope)")
	} else {
		e.printf("scopes:      %d glob(s)\n", len(p.Scopes))
		for _, glob := range sortedKeys(p.Scopes) {
			e.printf("  %s -> %s\n", glob, p.Scopes[glob])
		}
	}
	if len(p.Weights) > 0 {
		pairs := make([]string, 0, len(p.Weights))
		for _, scope := range sortedKeys(p.Weights) {
			pairs = append(pairs, fmt.Sprintf("%s=%s", scope, p.Weights[scope]))
		}
		e.printf("weights:     %s\n", strings.Join(pairs, ", "))
	}
	e.printf("meta-paths:  %s (required level %s)\n",
		strings.Join(p.Meta.Paths, ", "), p.Meta.RequiredLevel)
	if len(p.Derivations) == 0 {
		e.println("derivations: none")
	} else {
		names := make([]string, len(p.Derivations))
		for i, d := range p.Derivations {
			names[i] = d.Name
		}
		e.printf("derivations: %s\n", strings.Join(names, ", "))
	}
	e.printf("graph:       %s\n", p.GraphAdapter)
	return e.err
}

// strategyNote is the one-line §6.3 meaning of the configured strategy.
func strategyNote(s trust.Strategy) string {
	if s == trust.StrategyInflate {
		return "a demoting cell escalates the bump so default-range consumers do not auto-adopt (§6.3)"
	}
	return "a demoting cell confines the release to the trust pre-release channel (RECOMMENDED, §6.3)"
}

// demotionNote says what a demotion concretely produces under the strategy.
func demotionNote(s trust.Strategy) string {
	if s == trust.StrategyInflate {
		return "keeps the clean channel but escalates the bump (the escalation target is a policy choice, §6.3)"
	}
	return "keeps its semantically correct bump and is cut as v<core>-t<level>.<iteration> until evidence accumulates"
}

// sortedKeys returns m's keys sorted, for deterministic rendering.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
