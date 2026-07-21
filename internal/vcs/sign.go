// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/crypto/ssh"

	"github.com/semver-trust/semver-trust-go/internal/sshsig"
)

// ErrTagExists reports a refused tag creation: the tag name is already
// taken. Release tags are never overwritten — a re-cut is a new iteration
// (§7.2), not a moved ref.
var ErrTagExists = errors.New("tag already exists")

// CreateSignedTag writes an SSH-signed annotated tag (§10 step 9) named name
// at the commit target: the tag object's payload — object/type/tag/tagger
// headers plus the message — is SSHSIG-signed in the "git" namespace (the
// namespace git itself uses for tag and commit signatures, so `git tag -v`
// verifies the result against an allowed-signers file), and the armored
// signature is appended to the payload per git's signed-tag format.
//
// Everything ambient is injected (ADR-018): the tagger identity, the
// timestamp (never time.Now; encoded in UTC), and the signing key. target is
// a revision (tag, branch, or hash) resolved to its commit. It refuses to
// move an existing tag (ErrTagExists).
func CreateSignedTag(path, name, target, taggerName, taggerEmail, message string, when time.Time, signer ssh.Signer) error {
	apath, err := rootPath(path)
	if err != nil {
		return err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return err
	}
	commit, err := resolveCommit(r, target)
	if err != nil {
		return err
	}

	refName := plumbing.NewTagReferenceName(name)
	if _, err := r.Reference(refName, true); err == nil {
		return fmt.Errorf("%w: %s", ErrTagExists, name)
	} else if !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return err
	}

	// The message always ends with exactly one newline: go-git's encoder
	// concatenates message and signature verbatim, so a missing terminator
	// would corrupt the object.
	message = strings.TrimRight(message, "\n") + "\n"

	tag := &object.Tag{
		Name:       name,
		Tagger:     object.Signature{Name: taggerName, Email: taggerEmail, When: when.UTC()},
		Message:    message,
		TargetType: plumbing.CommitObject,
		Target:     commit.Hash,
	}

	// The signature covers the encoded tag object minus the signature
	// itself — the exact payload `git tag -v` reconstructs.
	payloadObj := &plumbing.MemoryObject{}
	if err := tag.EncodeWithoutSignature(payloadObj); err != nil {
		return err
	}
	payload, err := readEncoded(payloadObj)
	if err != nil {
		return err
	}
	armored, err := sshsig.Sign(signer, GitSSHNamespace, payload)
	if err != nil {
		return err
	}
	tag.PGPSignature = armored

	obj := r.Storer.NewEncodedObject()
	if err := tag.Encode(obj); err != nil {
		return err
	}
	hash, err := r.Storer.SetEncodedObject(obj)
	if err != nil {
		return err
	}
	return r.Storer.SetReference(plumbing.NewHashReference(refName, hash))
}

// TagExists reports whether a tag ref named name exists in the repository at
// path — the pre-flight a release runs before deciding is worth signing.
func TagExists(path, name string) (bool, error) {
	apath, err := rootPath(path)
	if err != nil {
		return false, err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return false, err
	}
	_, err = r.Reference(plumbing.NewTagReferenceName(name), true)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, plumbing.ErrReferenceNotFound):
		return false, nil
	default:
		return false, err
	}
}

// DeleteTag removes the tag ref refs/tags/<name>. It is the best-effort
// rollback for the release/v0.2 emit path (#76 M6): the tag is created before
// the attestation is signed so version_state.emission can bind its raw ref OID,
// so a signing failure must be able to undo the tag and restore the no-orphan
// property. A missing tag is not an error (the rollback is a no-op).
func DeleteTag(path, name string) error {
	apath, err := rootPath(path)
	if err != nil {
		return err
	}
	r, err := git.PlainOpenWithOptions(apath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return err
	}
	if err := r.Storer.RemoveReference(plumbing.NewTagReferenceName(name)); err != nil &&
		!errors.Is(err, plumbing.ErrReferenceNotFound) {
		return err
	}
	return nil
}

// readEncoded reads an encoded object's content bytes.
func readEncoded(obj plumbing.EncodedObject) ([]byte, error) {
	reader, err := obj.Reader()
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(reader)
	if closeErr := reader.Close(); err == nil {
		err = closeErr
	}
	return data, err
}
