// SPDX-License-Identifier: Apache-2.0

package enroll

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteRegistryCreatesAndReplaces(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".semver-trust"), 0o755); err != nil {
		t.Fatal(err)
	}
	rel := ".semver-trust/allowed_signers"

	// Create (parent exists, file absent).
	if err := WriteRegistry(repo, rel, []byte("one\n")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(repo, rel)); string(got) != "one\n" {
		t.Errorf("after create = %q, want %q", got, "one\n")
	}
	// Replace (file present) — atomic rename over the existing file.
	if err := WriteRegistry(repo, rel, []byte("one\ntwo\n")); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(repo, rel)); string(got) != "one\ntwo\n" {
		t.Errorf("after replace = %q, want %q", got, "one\ntwo\n")
	}

	// A successful write leaves no temp file behind.
	entries, _ := os.ReadDir(filepath.Join(repo, ".semver-trust"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".enroll-") {
			t.Errorf("leftover temp file %q", e.Name())
		}
	}
	// Registry mode is 0o644 (public trust material).
	if fi, _ := os.Stat(filepath.Join(repo, rel)); fi.Mode().Perm() != registryMode {
		t.Errorf("mode = %o, want %o", fi.Mode().Perm(), registryMode)
	}
}

func TestWriteRegistryRefusesMissingParent(t *testing.T) {
	repo := t.TempDir()
	// .semver-trust does not exist — a missing parent is a refusal, never MkdirAll.
	err := WriteRegistry(repo, ".semver-trust/allowed_signers", []byte("x\n"))
	if err == nil {
		t.Fatal("want a refusal for a missing parent directory")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %v, want a missing-parent refusal", err)
	}
	if _, statErr := os.Stat(filepath.Join(repo, ".semver-trust")); !os.IsNotExist(statErr) {
		t.Error("the tool must not have created the missing parent directory")
	}
}

func TestWriteRegistryFencesTraversal(t *testing.T) {
	repo := t.TempDir()
	if err := WriteRegistry(repo, "../escape", []byte("x\n")); err == nil {
		t.Error("a traversing path must be refused by the fence")
	}
	if err := WriteRegistry(repo, "/etc/passwd", []byte("x\n")); err == nil {
		t.Error("an absolute path must be refused by the fence")
	}
}
