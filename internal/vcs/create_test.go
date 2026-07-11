// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
)

// TestCreateTag creates an annotated tag with an injected fixed timestamp, then
// enumerates and reads it back to verify presence, tagger identity, message,
// target, and — the ADR-018 property — a deterministic timestamp.
func TestCreateTag(t *testing.T) {
	noTags, _ := buildFixtures(t)

	// The commit the fixture's build_repo made is the tag target.
	r, err := git.PlainOpen(noTags)
	if err != nil {
		t.Fatalf("PlainOpen: %v", err)
	}
	head, err := r.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	target := head.Hash()

	const (
		tagName = "v1.2.3"
		taggerN = "Release Bot"
		taggerE = "bot@semver-trust.test"
		message = "release v1.2.3"
	)
	when := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)

	if err := CreateTag(noTags, tagName, target, taggerN, taggerE, message, when); err != nil {
		t.Fatalf("CreateTag: %v", err)
	}

	// The tag enumerates through the ported surface.
	tags, err := Tags(noTags)
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if len(tags) != 1 || tags[0] != tagName {
		t.Fatalf("Tags after CreateTag = %v, want [%q]", tags, tagName)
	}

	// Read the annotated tag object back and verify every injected field. Reopen
	// so the read sees freshly written refs, not a stale in-memory handle.
	r2, err := git.PlainOpen(noTags)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	ref, err := r2.Tag(tagName)
	if err != nil {
		t.Fatalf("Tag(%q): %v", tagName, err)
	}
	obj, err := r2.TagObject(ref.Hash())
	if err != nil {
		t.Fatalf("TagObject: %v (tag is not annotated?)", err)
	}

	if obj.Target != target {
		t.Errorf("tag target = %s, want %s", obj.Target, target)
	}
	if obj.Tagger.Name != taggerN {
		t.Errorf("tagger name = %q, want %q", obj.Tagger.Name, taggerN)
	}
	if obj.Tagger.Email != taggerE {
		t.Errorf("tagger email = %q, want %q", obj.Tagger.Email, taggerE)
	}
	if strings.TrimSpace(obj.Message) != message {
		t.Errorf("message = %q, want %q", obj.Message, message)
	}
	// Deterministic timestamp: exactly the injected clock, never time.Now.
	if !obj.Tagger.When.Equal(when) {
		t.Errorf("tagger time = %s, want injected %s", obj.Tagger.When, when)
	}
}
