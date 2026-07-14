// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"fmt"
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

// PeeledRef is a tag ref resolved to both its raw target OID and the commit it
// ultimately peels to. For a lightweight tag the two are equal; for an
// annotated tag RefOID is the tag object and CommitOID is the commit it wraps.
// It is the shape the §7.5/ADR-029 version-ancestry ref-set (version.RefEntry)
// consumes, where distinguishing the raw ref target from the peeled commit is
// load-bearing.
type PeeledRef struct {
	RefOID    string
	CommitOID string
}

// TagRefs returns every tag of the repository at path as a map from short tag
// name to its raw ref OID and peeled commit OID. Annotated tags are peeled
// through the tag object to the commit; lightweight tags have RefOID equal to
// CommitOID. It is the production adapter feeding version-ancestry's authenticated
// ref-set — unlike Tags, which returns bare refnames, it exposes the object
// identities the evaluator binds against.
func TagRefs(path string) (map[string]PeeledRef, error) {
	apath, err := rootPath(path)
	if err != nil {
		return nil, err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, err
	}
	refs, err := r.Tags()
	if err != nil {
		return nil, err
	}

	out := map[string]PeeledRef{}
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		refOID := ref.Hash()
		var commitOID plumbing.Hash
		if tagObj, err := r.TagObject(refOID); err == nil {
			// Annotated tag: peel through the tag object to the commit it wraps.
			c, err := tagObj.Commit()
			if err != nil {
				return fmt.Errorf("tag refs: peeling annotated tag %q: %w", ref.Name().Short(), err)
			}
			commitOID = c.Hash
		} else {
			// Lightweight tag, or a ref updated to point directly at an object.
			// It MUST resolve to a commit: fail closed on a blob/tree/missing
			// target rather than manufacturing a commit identity, since this
			// feeds the authenticated §7.5 version-ancestry ref-set.
			c, err := r.CommitObject(refOID)
			if err != nil {
				return fmt.Errorf("tag refs: tag %q does not resolve to a commit: %w", ref.Name().Short(), err)
			}
			commitOID = c.Hash
		}
		out[ref.Name().Short()] = PeeledRef{RefOID: refOID.String(), CommitOID: commitOID.String()}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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
