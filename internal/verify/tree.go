// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// openRepo opens the repository at path with the same DetectDotGit posture as
// the vcs and attest entry points, so a path inside a working tree resolves to
// its repository root.
func openRepo(path string) (*git.Repository, error) {
	return git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: true})
}

// resolveCommit resolves a revision (tag, branch, or hash) to its commit.
func resolveCommit(r *git.Repository, rev string) (*object.Commit, error) {
	hash, err := r.ResolveRevision(plumbing.Revision(rev))
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", rev, err)
	}
	return r.CommitObject(*hash)
}

// ReadTreeFileIfPresent reads path from rev's tree for a drift comparison,
// distinguishing "there is nothing committed to compare against" from a genuine
// repository or object error:
//
//   - (data, true, nil)   path exists in rev's tree
//   - (nil, false, nil)   rev does not resolve (e.g. no commits yet) or path is
//                         absent from its tree — the expected fresh-repo states
//   - (nil, false, err)   a real error: the repository will not open, an object
//                         is unreadable or corrupt, or the blob read failed
//
// It is the P0 seam consumed by internal/preflight (doctor): the registry/policy
// drift checks compare the working-tree file against the tree at HEAD, and only a
// genuine error — not an absent HEAD or an as-yet-uncommitted file — should be
// surfaced as a problem. Every other tree read doctor needs is already behind an
// exported seam (LoadTrustMaterial, ClassifyCommit, MetaPolicyFromTree,
// AttestationVerifier).
func ReadTreeFileIfPresent(repoPath, rev, path string) (data []byte, present bool, err error) {
	r, err := openRepo(repoPath)
	if err != nil {
		return nil, false, err
	}
	commit, err := resolveCommit(r, rev)
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return nil, false, nil // no HEAD yet — nothing committed to compare against
		}
		return nil, false, err
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, false, err
	}
	f, err := tree.File(path)
	if err != nil {
		if errors.Is(err, object.ErrFileNotFound) || errors.Is(err, object.ErrDirectoryNotFound) {
			return nil, false, nil // path not in this tree — not yet committed
		}
		return nil, false, err
	}
	reader, err := f.Reader()
	if err != nil {
		return nil, false, err
	}
	data, err = io.ReadAll(reader)
	if closeErr := reader.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// readTreeFile reads a file from a revision's tree — never the working tree
// (§10 step 1: the policy is loaded from TO's tree, so a dirty checkout or a
// working-tree edit cannot change what is verified).
func readTreeFile(repoPath, rev, path string) ([]byte, error) {
	r, err := openRepo(repoPath)
	if err != nil {
		return nil, err
	}
	commit, err := resolveCommit(r, rev)
	if err != nil {
		return nil, err
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}
	f, err := tree.File(path)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", path, err)
	}
	reader, err := f.Reader()
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(reader)
	if closeErr := reader.Close(); err == nil {
		err = closeErr
	}
	return data, err
}

// exportTree materializes a revision's tree into destDir: the disposable
// checkout the graph adapter and compatibility differ consume (never the live
// working tree). File modes are preserved so the export is faithful.
func exportTree(repoPath, rev, destDir string) error {
	r, err := openRepo(repoPath)
	if err != nil {
		return err
	}
	commit, err := resolveCommit(r, rev)
	if err != nil {
		return err
	}
	tree, err := commit.Tree()
	if err != nil {
		return err
	}
	return tree.Files().ForEach(func(f *object.File) error {
		dest := filepath.Join(destDir, filepath.FromSlash(f.Name))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		reader, err := f.Reader()
		if err != nil {
			return err
		}
		perm := os.FileMode(0o644)
		if osMode, err := f.Mode.ToOSFileMode(); err == nil && osMode.Perm()&0o111 != 0 {
			perm = 0o755
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
		if err != nil {
			_ = reader.Close()
			return err
		}
		_, copyErr := io.Copy(out, reader)
		closeErr := out.Close()
		readerCloseErr := reader.Close()
		switch {
		case copyErr != nil:
			return copyErr
		case closeErr != nil:
			return closeErr
		default:
			return readerCloseErr
		}
	})
}

// exportToTemp exports a revision's tree into a fresh temp directory and
// returns it with a cleanup function. The caller owns cleanup.
func exportToTemp(repoPath, rev, pattern string) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", pattern)
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	if err := exportTree(repoPath, rev, dir); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return dir, cleanup, nil
}
