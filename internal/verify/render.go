// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// WriteJSON emits the report as indented JSON — the same content as the human
// table, in a machine-consumable shape.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// errWriter threads the first write error through a sequence of formatted
// writes, so the render below reads as a straight-line report rather than an
// error check after every line; the first failure short-circuits the rest.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, a...)
}

func (e *errWriter) println(a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintln(e.w, a...)
}

// WriteText renders the human-readable report: one row per commit plus a
// section per §10 step, each labeled with the step it traces to, so the output
// is a readable walk of the verification algorithm.
func (r *Report) WriteText(w io.Writer) error {
	e := &errWriter{w: w}

	e.printf("verify %s  (%s..%s)\n", r.Repo, orRoot(r.From), r.To)
	if r.ToCommit != "" {
		e.printf("TO commit: %s\n", r.ToCommit)
	}
	e.printf("verify-time: %s\n\n", r.VerifyTime)

	// §10 step 1 — policy + meta-path.
	e.println("[§10 step 1] policy")
	e.printf("  path:      %s\n", r.Policy.Path)
	e.printf("  digest:    sha256:%s\n", r.Policy.Digest)
	e.printf("  threshold: %s   strategy: %s   graph: %s\n", r.Policy.Threshold, r.Policy.Strategy, r.Policy.Adapter)
	if len(r.MetaPath.Paths) > 0 {
		e.printf("  meta-paths (%s required): %s — check %s\n",
			r.MetaPath.RequiredLevel, strings.Join(r.MetaPath.Paths, ", "), passFail(r.MetaPath.Passed))
	} else {
		e.println("  meta-paths: none declared")
	}

	// §10 steps 2–3 — per-commit provenance table. A boundary-anchored range
	// is disclosed first (ADR-024): the reader must never mistake "verified
	// since the boundary" for "verified since inception".
	e.println("\n[§10 steps 2–3] commits")
	if r.FromIsAdoptionBoundary {
		e.printf("  range: %s..%s (FROM is the adoption boundary declared in policy — history before it is exempt and makes no claim; ADR-024)\n",
			r.From, r.To)
	}
	r.writeCommitTable(e)
	for _, c := range r.Commits {
		if c.ReviewNote != "" {
			e.printf("  note %s: %s\n", c.Short, c.ReviewNote)
		}
		if c.Derivation != "" {
			e.printf("  note %s: outputs re-leveled by derivation %q (§4.4)\n", c.Short, c.Derivation)
		}
	}

	// §10 step 4 — derivation proofs.
	e.println("\n[§10 step 4] derivation proofs")
	if len(r.Derivations) == 0 {
		e.println("  none declared")
	}
	for _, d := range r.Derivations {
		switch {
		case d.Verified && d.InheritedLevel != "":
			e.printf("  %s: verified — outputs inherit %s\n", d.Rule, d.InheritedLevel)
		case d.Verified:
			e.printf("  %s: verified — %s\n", d.Rule, d.Note)
		default:
			e.printf("  %s: VOID (outputs keep own provenance) — differs: %s\n", d.Rule, strings.Join(d.Diffs, ", "))
		}
	}

	// §10 step 5 — own trust per scope.
	e.println("\n[§10 step 5] own trust (per scope)")
	for _, s := range r.Scopes {
		e.printf("  %s: %s  (commits: %s)\n", s.Scope, s.OwnFloor, strings.Join(s.Commits, ", "))
	}

	// §10 step 6 — effective trust after propagation.
	e.printf("\n[§10 step 6] effective trust (adapter: %s)\n", r.Propagation.Adapter)
	for _, c := range r.Propagation.Components {
		marker := ""
		if c.Name == r.Propagation.Target {
			marker = " <- target"
		}
		e.printf("  %s: own %s -> effective %s (floor source: %s)%s\n",
			c.Name, c.Own, c.Effective, c.FloorSource, marker)
	}
	if r.Propagation.Note != "" {
		e.printf("  note: %s\n", r.Propagation.Note)
	}

	// §10 step 7 — evidence.
	e.println("\n[§10 step 7] evidence")
	e.printf("  changed files: %d   changed LOC: %s\n", r.Evidence.ChangedFiles, available(r.Evidence.LOCAvailable))
	e.printf("  semantic floor: %s (from %s)\n", r.Evidence.SemanticFloor, r.Evidence.SemanticFloorSource)
	e.printf("  compatibility differ: %s\n", differState(r.Evidence))
	e.printf("  blast score: %s\n", r.Evidence.BlastScore)
	if r.Evidence.Note != "" {
		e.printf("  note: %s\n", r.Evidence.Note)
	}
	return e.err
}

// writeCommitTable renders the aligned per-commit provenance rows.
func (r *Report) writeCommitTable(e *errWriter) {
	if e.err != nil {
		return
	}
	tw := tabwriter.NewWriter(e.w, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "  SHA\tLEVEL\tAUTHORSHIP\tREVIEW\tSIGNER"); err != nil {
		e.err = err
		return
	}
	for _, c := range r.Commits {
		flags := ""
		if c.Merge {
			flags = " (merge)"
		}
		if _, err := fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s%s\n",
			c.Short, c.Level, c.Authorship, c.Review, c.Signer, flags); err != nil {
			e.err = err
			return
		}
	}
	e.err = tw.Flush()
}

func orRoot(from string) string {
	if from == "" {
		return "root"
	}
	return from
}

func passFail(ok bool) string {
	if ok {
		return "PASSED"
	}
	return "FAILED"
}

func available(ok bool) string {
	if ok {
		return "available"
	}
	return "unavailable"
}

func differState(e EvidenceReport) string {
	if e.DifferAvailable {
		return e.DifferProvider + " (available)"
	}
	return "unavailable"
}
