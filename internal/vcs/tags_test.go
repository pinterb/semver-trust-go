// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTags is the go-semver TestTags/TestNoTags suite, re-expressed against
// script-built local fixtures (audit §5.8: the donor cloned live GitHub repos).
// The tagged fixture must enumerate exactly the donor's six tags — lightweight
// and annotated alike — in go-git's lexicographic refname order.
func TestTags(t *testing.T) {
	noTags, tagged := buildFixtures(t)

	t.Run("tagged returns all six refs in order", func(t *testing.T) {
		got, err := Tags(tagged)
		if err != nil {
			t.Fatalf("Tags(%q) error: %v", tagged, err)
		}
		want := []string{
			"0.0.2",
			"0.1.0-alpha.0.beta",
			"0.1.0-alpha.01",
			"0.1.1-beta.0",
			"v0.0.1",
			"v0.1.0",
		}
		assertTags(t, got, want)
	})

	t.Run("no-tags returns empty without error", func(t *testing.T) {
		got, err := Tags(noTags)
		if err != nil {
			t.Fatalf("Tags(%q) error: %v", noTags, err)
		}
		if len(got) != 0 {
			t.Fatalf("expected no tags, got %d: %v", len(got), got)
		}
	})

	t.Run("DetectDotGit finds repo from a subdirectory", func(t *testing.T) {
		sub := filepath.Join(tagged, "nested", "deeper")
		if err := os.MkdirAll(sub, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		got, err := Tags(sub)
		if err != nil {
			t.Fatalf("Tags(%q) error: %v", sub, err)
		}
		if len(got) != 6 {
			t.Fatalf("expected 6 tags from subdirectory, got %d: %v", len(got), got)
		}
	})

	t.Run("regular-file path resolves to its parent directory", func(t *testing.T) {
		file := filepath.Join(tagged, "a-file")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		got, err := Tags(file)
		if err != nil {
			t.Fatalf("Tags(%q) error: %v", file, err)
		}
		if len(got) != 6 {
			t.Fatalf("expected 6 tags via file's parent, got %d: %v", len(got), got)
		}
	})

	t.Run("non-repository path errors", func(t *testing.T) {
		if _, err := Tags(t.TempDir()); err == nil {
			t.Fatal("expected an error opening a non-repository directory, got nil")
		}
	})
}

func assertTags(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d tags %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tag[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}
