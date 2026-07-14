// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitCmd runs git in repo with identity + signing pinned per-invocation, so the
// test is independent of the caller's git config (which in this repo signs).
func gitCmd(t *testing.T, repo string, args ...string) string {
	t.Helper()
	base := []string{
		"-C", repo,
		"-c", "init.defaultBranch=main",
		"-c", "user.name=SemVer-Trust Graph Fixture",
		"-c", "user.email=graph@semver-trust.test",
		"-c", "commit.gpgsign=false",
		"-c", "tag.gpgsign=false",
	}
	out, err := exec.Command("git", append(base, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// buildGraphRepo builds a repository with a known DAG that includes a merge:
//
//	root ── A ── C ─────┐
//	         └── B ─────┴── M (HEAD)
//
// so CommitGraph is exercised over multi-parent history. Returns the repo path.
func buildGraphRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	gitCmd(t, repo, "init", "--quiet")
	gitCmd(t, repo, "commit", "--quiet", "--allow-empty", "-m", "root")
	gitCmd(t, repo, "commit", "--quiet", "--allow-empty", "-m", "A")
	gitCmd(t, repo, "branch", "feature")
	gitCmd(t, repo, "commit", "--quiet", "--allow-empty", "-m", "C")
	gitCmd(t, repo, "checkout", "--quiet", "feature")
	gitCmd(t, repo, "commit", "--quiet", "--allow-empty", "-m", "B")
	gitCmd(t, repo, "checkout", "--quiet", "main")
	gitCmd(t, repo, "merge", "--no-ff", "--no-edit", "feature", "-m", "M")
	return repo
}

// TestCommitGraph checks the parent-annotated graph builder against git's own
// reachability (`git rev-list --parents`), and confirms the result round-trips
// through the evaluator reachability helper the interval/version-ancestry
// oracles use.
func TestCommitGraph(t *testing.T) {
	repo := buildGraphRepo(t)

	got, err := CommitGraph(repo, "HEAD")
	if err != nil {
		t.Fatalf("CommitGraph: %v", err)
	}

	// Oracle: git rev-list --parents lists <commit> <parent...> per line for
	// every commit reachable from HEAD — exactly CommitNode{ID,Parents}.
	want := map[string][]string{}
	for _, line := range strings.Split(gitCmd(t, repo, "rev-list", "--parents", "HEAD"), "\n") {
		fields := strings.Fields(line)
		want[fields[0]] = fields[1:]
	}
	if len(got) != len(want) {
		t.Fatalf("got %d nodes, want %d (%v)", len(got), len(want), want)
	}

	gotByID := map[string][]string{}
	for _, n := range got {
		gotByID[n.ID] = n.Parents
	}
	var merges int
	for id, wantParents := range want {
		gotParents, ok := gotByID[id]
		if !ok {
			t.Errorf("node %s missing from CommitGraph output", id)
			continue
		}
		if !equalSlice(gotParents, wantParents) {
			t.Errorf("node %s parents = %v, want %v", id, gotParents, wantParents)
		}
		if len(wantParents) > 1 {
			merges++
		}
	}
	if merges != 1 {
		t.Errorf("expected exactly one merge node in the fixture, saw %d", merges)
	}

	// Round-trip: the parent map the adapter emits must let the evaluators'
	// reachability helper reach every node from HEAD.
	head := gitCmd(t, repo, "rev-parse", "HEAD")
	parents := map[string][]string{}
	for _, n := range got {
		parents[n.ID] = n.Parents
	}
	reach := commitReach(head, parents)
	if len(reach) != len(got) {
		t.Errorf("commitReach(HEAD) reached %d of %d nodes", len(reach), len(got))
	}
}

func TestCommitGraphSingleCommit(t *testing.T) {
	noTags, _ := buildFixtures(t)
	got, err := CommitGraph(noTags, "HEAD")
	if err != nil {
		t.Fatalf("CommitGraph: %v", err)
	}
	if len(got) != 1 || len(got[0].Parents) != 0 {
		t.Fatalf("single-commit graph = %+v, want one parentless node", got)
	}
}

func TestCommitGraphErrors(t *testing.T) {
	if _, err := CommitGraph(t.TempDir(), "HEAD"); err == nil {
		t.Error("expected an error opening a non-repository directory")
	}
	repo := buildGraphRepo(t)
	if _, err := CommitGraph(repo, "no-such-rev"); err == nil {
		t.Error("expected an error resolving an unknown revision")
	}
}

// TestTagRefs checks the peeled ref-set: lightweight tags have RefOID equal to
// CommitOID, annotated tags peel through the tag object to the commit, and every
// peeled CommitOID matches ResolveCommit for the same tag.
func TestTagRefs(t *testing.T) {
	_, tagged := buildFixtures(t)

	refs, err := TagRefs(tagged)
	if err != nil {
		t.Fatalf("TagRefs: %v", err)
	}

	lightweight := []string{"0.0.2", "0.1.0-alpha.0.beta", "v0.0.1"}
	annotated := []string{"0.1.0-alpha.01", "0.1.1-beta.0", "v0.1.0"}
	if len(refs) != len(lightweight)+len(annotated) {
		t.Fatalf("got %d refs, want 6: %v", len(refs), refs)
	}

	// The whole fixture sits on one commit; every peeled CommitOID is HEAD.
	head, err := ResolveCommit(tagged, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range lightweight {
		r := refs[tag]
		if r.RefOID != r.CommitOID {
			t.Errorf("lightweight %s: RefOID %s != CommitOID %s", tag, r.RefOID, r.CommitOID)
		}
		if r.CommitOID != head {
			t.Errorf("%s peels to %s, want HEAD %s", tag, r.CommitOID, head)
		}
	}
	for _, tag := range annotated {
		r := refs[tag]
		if r.RefOID == r.CommitOID {
			t.Errorf("annotated %s: RefOID should be the tag object, not the commit %s", tag, r.CommitOID)
		}
		if r.CommitOID != head {
			t.Errorf("%s peels to %s, want HEAD %s", tag, r.CommitOID, head)
		}
		resolved, err := ResolveCommit(tagged, tag)
		if err != nil {
			t.Fatal(err)
		}
		if resolved != r.CommitOID {
			t.Errorf("%s: ResolveCommit %s != peeled CommitOID %s", tag, resolved, r.CommitOID)
		}
	}
}

func TestTagRefsEmptyAndError(t *testing.T) {
	noTags, _ := buildFixtures(t)
	refs, err := TagRefs(noTags)
	if err != nil {
		t.Fatalf("TagRefs(no-tags): %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("expected no refs, got %v", refs)
	}
	if _, err := TagRefs(t.TempDir()); err == nil {
		t.Error("expected an error opening a non-repository directory")
	}
}

// TestTagRefsFailsClosedOnNonCommitTag proves the adapter never manufactures a
// commit identity for a tag ref that points at a non-commit object: a
// lightweight tag updated to a blob hash must abort, not report the blob as the
// peeled CommitOID (it feeds the authenticated §7.5 ref-set).
func TestTagRefsFailsClosedOnNonCommitTag(t *testing.T) {
	repo := buildGraphRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "blob.txt"), []byte("not a commit"), 0o600); err != nil {
		t.Fatal(err)
	}
	blob := gitCmd(t, repo, "hash-object", "-w", "blob.txt")
	gitCmd(t, repo, "update-ref", "refs/tags/v1.2.3", blob)

	if _, err := TagRefs(repo); err == nil {
		t.Fatal("expected TagRefs to fail closed on a tag ref pointing at a blob, got nil")
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
