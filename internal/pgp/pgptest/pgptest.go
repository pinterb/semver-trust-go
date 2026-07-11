// SPDX-License-Identifier: Apache-2.0

// Package pgptest generates OpenPGP test material for the GPG key-family
// tests: per-run Ed25519 entities with pinned creation times, armored public
// keyrings, and fixture repositories carrying real GPG-signed commits —
// hermetic (no network, no gpg binary), with every instant injected
// (ADR-018).
//
// Keys are generated per test run rather than vendored: the
// cross-implementation vendored-GPG-fixture question is explicitly deferred
// to a future spec-repo round (fixture plan §2.1, §7 OQ3).
package pgptest

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// NewSigner generates an Ed25519 OpenPGP entity whose primary key is created
// at the injected instant. lifetimeSecs of zero means no expiry; a non-zero
// value lets a test build a key that is expired at a later verification
// instant.
func NewSigner(name, email string, at time.Time, lifetimeSecs uint32) (*openpgp.Entity, error) {
	config := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Time:            func() time.Time { return at },
		KeyLifetimeSecs: lifetimeSecs,
	}
	return openpgp.NewEntity(name, "semver-trust TEST KEY - DO NOT USE", email, config)
}

// ArmoredKeyring serializes the public halves of the entities as one armored
// keyring — the bytes a caller injects as GPG trust material.
func ArmoredKeyring(entities ...*openpgp.Entity) ([]byte, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	for _, e := range entities {
		if err := e.Serialize(w); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	// go-crypto's armor encoder ends without a newline; gpg --export --armor
	// emits one. Match gpg so concatenated keyrings look like the real thing.
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// emptyTree is git's well-known empty tree object (zero entries).
var emptyTreeHash = plumbing.NewHash("4b825dc642cb6eb9a060e54bf8d69288fbee4904")

// NewRepoWithSignedCommit initializes a git repository at dir whose single
// (root) commit is genuinely GPG-signed by signer at the injected instant:
// the commit payload bytes are detached-signed with go-crypto and the
// armored signature is assembled into the raw commit object as its gpgsig
// header — the same construction git performs with the gpg binary, without
// the binary. It returns the signed commit's hash.
func NewRepoWithSignedCommit(dir string, signer *openpgp.Entity, at time.Time, message string) (string, error) {
	return buildSignedCommit(dir, signer, at, message, message)
}

// NewRepoWithTamperedCommit is NewRepoWithSignedCommit with the commit
// message altered after signing: the stored object carries a structurally
// valid signature that does not cover the stored bytes.
func NewRepoWithTamperedCommit(dir string, signer *openpgp.Entity, at time.Time, message string) (string, error) {
	return buildSignedCommit(dir, signer, at, message, "tampered: "+message)
}

// buildSignedCommit signs the payload carrying signedMessage and stores a
// commit object carrying storedMessage; identical messages yield a verifying
// commit, differing ones a tampered one.
func buildSignedCommit(dir string, signer *openpgp.Entity, at time.Time, signedMessage, storedMessage string) (string, error) {
	r, err := git.PlainInit(dir, false)
	if err != nil {
		return "", err
	}

	// Store the empty tree so the root commit's tree reference resolves.
	treeObj := r.Storer.NewEncodedObject()
	treeObj.SetType(plumbing.TreeObject)
	tw, err := treeObj.Writer()
	if err != nil {
		return "", err
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	treeHash, err := r.Storer.SetEncodedObject(treeObj)
	if err != nil {
		return "", err
	}
	if treeHash != emptyTreeHash {
		return "", fmt.Errorf("empty tree hashed to %s, want %s", treeHash, emptyTreeHash)
	}

	sig, err := detachSign(signer, commitPayload(treeHash, at, signedMessage), at)
	if err != nil {
		return "", err
	}
	raw := assembleSignedCommit(commitPayload(treeHash, at, storedMessage), sig)

	commitObj := r.Storer.NewEncodedObject()
	commitObj.SetType(plumbing.CommitObject)
	cw, err := commitObj.Writer()
	if err != nil {
		return "", err
	}
	if _, err := cw.Write(raw); err != nil {
		return "", err
	}
	if err := cw.Close(); err != nil {
		return "", err
	}
	hash, err := r.Storer.SetEncodedObject(commitObj)
	if err != nil {
		return "", err
	}

	main := plumbing.NewBranchReferenceName("main")
	if err := r.Storer.SetReference(plumbing.NewHashReference(main, hash)); err != nil {
		return "", err
	}
	if err := r.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, main)); err != nil {
		return "", err
	}
	return hash.String(), nil
}

// commitPayload builds the exact bytes git's gpgsig covers: the commit
// object without its signature header, byte-identical to what go-git's
// EncodeWithoutSignature reproduces for the stored commit.
func commitPayload(tree plumbing.Hash, at time.Time, message string) []byte {
	ident := fmt.Sprintf("gpg-signer <gpg-signer@semver-trust.test> %d +0000", at.Unix())
	return fmt.Appendf(nil, "tree %s\nauthor %s\ncommitter %s\n\n%s", tree, ident, ident, message)
}

// detachSign produces the armored detached signature over payload, with the
// signature's creation time pinned to the injected instant. Binary signature
// type: what git produces when it pipes the commit object to gpg.
func detachSign(signer *openpgp.Entity, payload []byte, at time.Time) (string, error) {
	config := &packet.Config{Time: func() time.Time { return at }}
	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&buf, signer, bytes.NewReader(payload), config); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// assembleSignedCommit inserts the armored signature into the raw payload as
// a gpgsig header before the blank line, with continuation lines
// space-prefixed — git's multi-line header encoding.
func assembleSignedCommit(payload []byte, armoredSig string) []byte {
	headers, body, _ := bytes.Cut(payload, []byte("\n\n"))
	gpgsig := "gpgsig " + strings.ReplaceAll(strings.TrimSuffix(armoredSig, "\n"), "\n", "\n ")
	var raw bytes.Buffer
	raw.Write(headers)
	raw.WriteByte('\n')
	raw.WriteString(gpgsig)
	raw.WriteString("\n\n")
	raw.Write(body)
	return raw.Bytes()
}
