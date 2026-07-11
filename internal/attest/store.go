// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// Store is the attestation-storage seam (§8.2). Storage is never the trust
// anchor — the signature inside the attestation is — so adapters are plain
// dumb transports: they neither verify nor interpret envelopes.
type Store interface {
	// Put stores an envelope for a subject (a commit SHA or tag name) and
	// returns an opaque reference to it. Storing the same bytes twice is
	// idempotent.
	Put(subject string, envelope []byte) (string, error)
	// List returns every stored envelope for a subject, supersessions
	// included — supersession is expressed by publishing, never by mutating
	// or deleting (§7.3.5).
	List(subject string) ([][]byte, error)
}

// GitRefStore stores envelopes as blobs referenced under
// refs/attestations/<subject>/<digest> in a git repository — the first
// adapter (GO-033), keeping attestations inside the repository they attest.
type GitRefStore struct {
	// Path is the repository path (resolved like the other vcs entry
	// points: DetectDotGit applies).
	Path string
}

const refPrefix = "refs/attestations/"

// Put writes the envelope blob and a ref naming it. The ref leaf is the
// envelope's content digest, so distinct attestations for one subject
// coexist and re-putting identical bytes is a no-op.
func (s GitRefStore) Put(subject string, envelope []byte) (string, error) {
	if err := validSubject(subject); err != nil {
		return "", err
	}
	r, err := git.PlainOpenWithOptions(s.Path, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", err
	}

	obj := r.Storer.NewEncodedObject()
	obj.SetType(plumbing.BlobObject)
	w, err := obj.Writer()
	if err != nil {
		return "", err
	}
	if _, err := w.Write(envelope); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	blob, err := r.Storer.SetEncodedObject(obj)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(envelope)
	ref := refPrefix + subject + "/" + hex.EncodeToString(sum[:12])
	if err := r.Storer.SetReference(plumbing.NewHashReference(plumbing.ReferenceName(ref), blob)); err != nil {
		return "", err
	}
	return ref, nil
}

// List returns the stored envelopes for a subject, in ref order.
func (s GitRefStore) List(subject string) ([][]byte, error) {
	if err := validSubject(subject); err != nil {
		return nil, err
	}
	r, err := git.PlainOpenWithOptions(s.Path, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, err
	}
	refs, err := r.References()
	if err != nil {
		return nil, err
	}

	prefix := refPrefix + subject + "/"
	var envelopes [][]byte
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if !strings.HasPrefix(ref.Name().String(), prefix) {
			return nil
		}
		blob, err := r.BlobObject(ref.Hash())
		if err != nil {
			return err
		}
		reader, err := blob.Reader()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(reader)
		if closeErr := reader.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		envelopes = append(envelopes, data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return envelopes, nil
}

// validSubject keeps subjects inside the ref namespace: a subject that could
// escape refs/attestations/ (path traversal, ref syntax) is rejected rather
// than sanitized.
func validSubject(subject string) error {
	switch {
	case subject == "",
		strings.Contains(subject, ".."),
		strings.HasPrefix(subject, "/"),
		strings.HasSuffix(subject, "/"),
		strings.ContainsAny(subject, " ~^:?*[\\"):
		return fmt.Errorf("attest: invalid subject %q", subject)
	}
	return nil
}
