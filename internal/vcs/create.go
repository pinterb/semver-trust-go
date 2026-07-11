// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// CreateTag writes an annotated tag named name at the object target in the
// repository at path, tagged by taggerName/taggerEmail with the given message.
//
// The tagger timestamp is the injected when, never time.Now: verification-shaped
// packages take an injected clock so tagging is deterministic and testable
// (ADR-018, plan §6). The tagger identity is passed in rather than read from
// git config, so the operation needs no ambient environment. path is resolved
// the same way as Tags (see rootPath). Signing is out of scope (GO-042).
func CreateTag(path, name string, target plumbing.Hash, taggerName, taggerEmail, message string, when time.Time) error {
	apath, err := rootPath(path)
	if err != nil {
		return err
	}

	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return err
	}

	_, err = r.CreateTag(name, target, &git.CreateTagOptions{
		Tagger: &object.Signature{
			Name:  taggerName,
			Email: taggerEmail,
			When:  when,
		},
		Message: message,
	})
	return err
}
