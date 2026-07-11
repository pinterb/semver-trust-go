// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"errors"
	"fmt"
	"sort"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// RangeCommit is one commit of a release range, carrying everything
// downstream verification consumes: the trailer block (§4.1) and the diff
// paths that scope partitioning keys off (§5.1). For merge commits, Paths
// holds only the novel paths (§4.3.4) — see novelPaths.
type RangeCommit struct {
	Hash     string
	Subject  string
	Message  string
	Trailers Trailers
	Paths    []string
	Merge    bool
}

// Range enumerates the commits of FROM..TO — commits reachable from TO and
// not from FROM (git two-dot; §5.2) — against the repository at path. An
// empty FROM means a first release: root..TO, every commit (§10 step 2).
// FROM and TO are revisions (tag names, branch names, or hashes).
//
// FROM MUST be an ancestor of TO: a previous release tag that is no longer
// reachable from the release head means the protected branch's history was
// rewritten, which invalidates prior tags' ranges and MUST be treated as
// verification failure (§10.2) — reported here as an error, never as an
// empty or partial range.
func Range(path, from, to string) ([]RangeCommit, error) {
	apath, err := rootPath(path)
	if err != nil {
		return nil, err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, err
	}

	toCommit, err := resolveCommit(r, to)
	if err != nil {
		return nil, fmt.Errorf("range: resolving TO %q: %w", to, err)
	}

	exclude := map[plumbing.Hash]bool{}
	if from != "" {
		fromCommit, err := resolveCommit(r, from)
		if err != nil {
			return nil, fmt.Errorf("range: resolving FROM %q: %w", from, err)
		}
		ancestor, err := fromCommit.IsAncestor(toCommit)
		if err != nil {
			return nil, err
		}
		if !ancestor {
			return nil, fmt.Errorf(
				"range: %s is not an ancestor of %s: history was rewritten, invalidating this range (§10.2)",
				from, to,
			)
		}
		if exclude, err = ancestors(fromCommit); err != nil {
			return nil, err
		}
	}

	var commits []RangeCommit
	iter := object.NewCommitPreorderIter(toCommit, exclude, nil)
	err = iter.ForEach(func(c *object.Commit) error {
		paths, err := changedPaths(c)
		if err != nil {
			return err
		}
		message := c.Message
		commits = append(commits, RangeCommit{
			Hash:     c.Hash.String(),
			Subject:  firstLine(message),
			Message:  message,
			Trailers: ParseTrailers(message),
			Paths:    paths,
			Merge:    c.NumParents() > 1,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return commits, nil
}

// ancestors returns c and every commit reachable from it.
func ancestors(c *object.Commit) (map[plumbing.Hash]bool, error) {
	seen := map[plumbing.Hash]bool{}
	iter := object.NewCommitPreorderIter(c, nil, nil)
	err := iter.ForEach(func(a *object.Commit) error {
		seen[a.Hash] = true
		return nil
	})
	return seen, err
}

// changedPaths returns the paths a commit changes: every path for a root
// commit, the diff against the sole parent for ordinary commits, and the
// novel paths for merge commits (§4.3.4).
func changedPaths(c *object.Commit) ([]string, error) {
	switch c.NumParents() {
	case 0:
		return allPaths(c)
	case 1:
		parent, err := c.Parent(0)
		if err != nil {
			return nil, err
		}
		return diffPaths(parent, c)
	default:
		return novelPaths(c)
	}
}

func allPaths(c *object.Commit) ([]string, error) {
	var paths []string
	files, err := c.Files()
	if err != nil {
		return nil, err
	}
	err = files.ForEach(func(f *object.File) error {
		paths = append(paths, f.Name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

// diffPaths returns the paths differing between two commits' trees; a rename
// contributes both names.
func diffPaths(from, to *object.Commit) ([]string, error) {
	fromTree, err := from.Tree()
	if err != nil {
		return nil, err
	}
	toTree, err := to.Tree()
	if err != nil {
		return nil, err
	}
	changes, err := fromTree.Diff(toTree)
	if err != nil {
		return nil, err
	}

	set := map[string]bool{}
	for _, ch := range changes {
		if ch.From.Name != "" {
			set[ch.From.Name] = true
		}
		if ch.To.Name != "" {
			set[ch.To.Name] = true
		}
	}
	paths := make([]string, 0, len(set))
	for p := range set {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, nil
}

// novelPaths returns the paths whose content in a merge commit matches no
// parent: conflict resolutions and anything else smuggled into the merge are
// authored changes and MUST be classified like any other commit's — the
// resolver is their author, and the PR's review attestation does not
// automatically cover them (§4.3.4).
//
// A path adopted verbatim from either parent is not novel. A file both sides
// modified whose textual merge succeeded cleanly differs from both parents
// and IS reported — a deliberate over-approximation: it errs toward
// classifying more of the merge as authored, never less, so trust levels can
// only floor lower than the precise answer, in keeping with §5.1's
// no-de-minimis posture.
func novelPaths(c *object.Commit) ([]string, error) {
	candidates := map[string]bool{}
	for i := 0; i < c.NumParents(); i++ {
		parent, err := c.Parent(i)
		if err != nil {
			return nil, err
		}
		paths, err := diffPaths(parent, c)
		if err != nil {
			return nil, err
		}
		for _, p := range paths {
			candidates[p] = true
		}
	}

	var novel []string
	for path := range candidates {
		own, err := entryHash(c, path)
		if err != nil {
			return nil, err
		}
		adopted := false
		for i := 0; i < c.NumParents(); i++ {
			parent, err := c.Parent(i)
			if err != nil {
				return nil, err
			}
			parentEntry, err := entryHash(parent, path)
			if err != nil {
				return nil, err
			}
			if own == parentEntry {
				adopted = true
				break
			}
		}
		if !adopted {
			novel = append(novel, path)
		}
	}
	sort.Strings(novel)
	return novel, nil
}

// entryHash returns the blob hash of path in the commit's tree, or the zero
// hash when the path is absent (so a deletion matching a parent's deletion
// compares as adopted).
func entryHash(c *object.Commit, path string) (plumbing.Hash, error) {
	tree, err := c.Tree()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	entry, err := tree.FindEntry(path)
	if err != nil {
		if errors.Is(err, object.ErrEntryNotFound) || errors.Is(err, object.ErrDirectoryNotFound) {
			return plumbing.ZeroHash, nil
		}
		return plumbing.ZeroHash, err
	}
	return entry.Hash, nil
}

// ResolveCommit resolves a revision (tag name, branch name, abbreviated or
// full hash) to its full commit SHA against the repository at path. Callers
// that key storage or subjects off commit identity resolve through here so a
// short hash or tag never becomes a storage key.
func ResolveCommit(path, rev string) (string, error) {
	apath, err := rootPath(path)
	if err != nil {
		return "", err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", err
	}
	c, err := resolveCommit(r, rev)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w", rev, err)
	}
	return c.Hash.String(), nil
}

func resolveCommit(r *git.Repository, rev string) (*object.Commit, error) {
	hash, err := r.ResolveRevision(plumbing.Revision(rev))
	if err != nil {
		return nil, err
	}
	return r.CommitObject(*hash)
}

func firstLine(message string) string {
	for i := 0; i < len(message); i++ {
		if message[i] == '\n' {
			return message[:i]
		}
	}
	return message
}
