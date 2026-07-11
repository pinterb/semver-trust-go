// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// buildWalkFixtures runs scripts/build-walk-fixtures.sh into a fresh temp
// directory and returns it. Hermetic: local repositories, no network.
func buildWalkFixtures(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file to find the fixture script")
	}
	script := filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts", "build-walk-fixtures.sh")

	dest := t.TempDir()
	cmd := exec.Command("bash", script, dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-walk-fixtures.sh failed: %v\n%s", err, out)
	}
	return dest
}

func commitBySubject(t *testing.T, commits []RangeCommit, subject string) RangeCommit {
	t.Helper()
	for _, c := range commits {
		if c.Subject == subject {
			return c
		}
	}
	t.Fatalf("no commit with subject %q in %v", subject, subjects(commits))
	return RangeCommit{}
}

func subjects(commits []RangeCommit) []string {
	out := make([]string, len(commits))
	for i, c := range commits {
		out[i] = c.Subject
	}
	return out
}

func TestRangeFirstRelease(t *testing.T) {
	repo := filepath.Join(buildWalkFixtures(t), "first-release")

	// An empty FROM is a first release: root..TO enumerates every commit.
	commits, err := Range(repo, "", "main")
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(commits) != 3 {
		t.Fatalf("first release walked %d commits, want 3: %v", len(commits), subjects(commits))
	}

	root := commitBySubject(t, commits, "feat: seed common")
	if root.Merge {
		t.Error("root commit flagged as merge")
	}
	if !reflect.DeepEqual(root.Paths, []string{"pkg/common/util.go"}) {
		t.Errorf("root paths = %v", root.Paths)
	}
	if got := root.Trailers.Provenance(); got != "human" {
		t.Errorf("root provenance = %q", got)
	}

	auth := commitBySubject(t, commits, "feat: auth handler")
	if got := auth.Trailers.Provenance(); got != "agent" {
		t.Errorf("auth provenance = %q", got)
	}
	if got, _ := auth.Trailers.Get(TrailerProvenanceAgent); got != "fixture-agent/1.0" {
		t.Errorf("auth Provenance-Agent = %q", got)
	}
	if !reflect.DeepEqual(auth.Paths, []string{"services/auth/handler.go"}) {
		t.Errorf("auth paths = %v", auth.Paths)
	}
}

func TestRangeFromTag(t *testing.T) {
	repo := filepath.Join(buildWalkFixtures(t), "first-release")

	// v0.1.0..main excludes everything reachable from the tag.
	commits, err := Range(repo, "v0.1.0", "main")
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("range walked %d commits, want 1: %v", len(commits), subjects(commits))
	}
	docs := commits[0]
	if docs.Subject != "docs: auth notes" {
		t.Errorf("subject = %q", docs.Subject)
	}
	if got := docs.Trailers.Provenance(); got != "mixed" {
		t.Errorf("provenance = %q", got)
	}
	if !reflect.DeepEqual(docs.Paths, []string{"docs/auth.md"}) {
		t.Errorf("paths = %v", docs.Paths)
	}
}

// TestRangeCleanMerge covers the merge-commits-only history the scheme
// mandates in place of squash/rebase merging (§4.3.3): the walk sees both
// branches' commits plus the merge commit, and a clean merge — every path
// adopted from a parent — carries no novel paths.
func TestRangeCleanMerge(t *testing.T) {
	repo := filepath.Join(buildWalkFixtures(t), "merged")

	commits, err := Range(repo, "base", "main")
	if err != nil {
		t.Fatalf("Range: %v", err)
	}
	if len(commits) != 3 {
		t.Fatalf("walked %d commits, want 3 (both sides + merge): %v", len(commits), subjects(commits))
	}

	merge := commitBySubject(t, commits, "merge: feature (clean)")
	if !merge.Merge {
		t.Error("merge commit not flagged as merge")
	}
	if len(merge.Paths) != 0 {
		t.Errorf("clean merge has novel paths %v, want none (§4.3.4)", merge.Paths)
	}
	for _, subject := range []string{"feat: feature side", "feat: main side"} {
		c := commitBySubject(t, commits, subject)
		if c.Merge || len(c.Paths) != 1 {
			t.Errorf("%q: merge=%v paths=%v", subject, c.Merge, c.Paths)
		}
	}
}

// TestRangeConflictedMerge covers §4.3.4: a conflict resolution's content
// matches neither parent, so the merge commit carries the resolved path as
// an authored change — the resolver is its author.
func TestRangeConflictedMerge(t *testing.T) {
	repo := filepath.Join(buildWalkFixtures(t), "conflicted")

	commits, err := Range(repo, "base", "main")
	if err != nil {
		t.Fatalf("Range: %v", err)
	}

	merge := commitBySubject(t, commits, "merge: feature (conflict resolved)")
	if !merge.Merge {
		t.Error("merge commit not flagged as merge")
	}
	if !reflect.DeepEqual(merge.Paths, []string{"conflict.txt"}) {
		t.Errorf("novel paths = %v, want [conflict.txt] (§4.3.4)", merge.Paths)
	}
}

// TestRangeRewrittenHistory covers §10.2: a FROM no longer reachable from TO
// means the protected branch was rewritten; the range is invalid and must
// error, never come back empty or partial.
func TestRangeRewrittenHistory(t *testing.T) {
	repo := filepath.Join(buildWalkFixtures(t), "rewritten")

	_, err := Range(repo, "released", "main")
	if err == nil {
		t.Fatal("Range accepted a rewritten history")
	}
	if !strings.Contains(err.Error(), "history was rewritten") {
		t.Errorf("error = %q, want a history-rewrite explanation", err)
	}
}

func TestRangeResolutionErrors(t *testing.T) {
	repo := filepath.Join(buildWalkFixtures(t), "first-release")

	if _, err := Range(repo, "", "no-such-rev"); err == nil {
		t.Error("Range accepted an unresolvable TO")
	}
	if _, err := Range(repo, "no-such-rev", "main"); err == nil {
		t.Error("Range accepted an unresolvable FROM")
	}
	if _, err := Range(t.TempDir(), "", "main"); err == nil {
		t.Error("Range accepted a non-repository path")
	}
}
