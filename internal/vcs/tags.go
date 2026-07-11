// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// Tags returns every tag ref of the git repository at path — both lightweight
// and annotated tags — as the short refnames (the "0.0.2" of
// "refs/tags/0.0.2"), in the repository's own ref-iteration order (go-git
// yields refs lexicographically by refname). It is raw enumeration: the values
// are not parsed, filtered, or SemVer-sorted here; ParseTags and Latest layer
// that on top.
//
// path is resolved by rootPath: empty means the current directory, a regular
// file resolves to its parent directory, and a directory is used as-is. The
// repository is opened with DetectDotGit, so a path inside a working tree finds
// the enclosing repository.
//
// Ported from go-semver's git.Tags, replacing the abandoned
// gopkg.in/src-d/go-git.v4 dependency with github.com/go-git/go-git/v5; the
// enumeration semantics are unchanged.
func Tags(path string) ([]string, error) {
	apath, err := rootPath(path)
	if err != nil {
		return nil, err
	}

	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, err
	}

	// All tag references, both lightweight tags and annotated tags.
	refs, err := r.Tags()
	if err != nil {
		return nil, err
	}

	tags := make([]string, 0)
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		tags = append(tags, ref.Name().Short())
		return nil
	})
	if err != nil {
		return nil, err
	}
	return tags, nil
}

// rootPath resolves path to a directory to open a repository in: an empty path
// becomes the current working directory, a regular-file path becomes its parent
// directory, and a directory path is returned unchanged. It does not walk up to
// the repository root — DetectDotGit handles that at open time. Ported from
// go-semver's git.rootPath.
func rootPath(path string) (string, error) {
	if path == "" {
		dir, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return dir, nil
	}

	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().IsRegular() {
		if dir := filepath.Dir(path); dir != path {
			return dir, nil
		}
	}
	return path, nil
}
