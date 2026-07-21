// SPDX-License-Identifier: Apache-2.0

// Package enroll generates, formats, and validates trust-material enrollments —
// SSH allowed-signers lines and GPG keyring entries — and, opt-in, writes them
// into the working-tree registry under a strict atomic contract. It never stages,
// commits, or signs: the tool generates and validates; the human enrolls, commits,
// and signs (ADR-038). Every write obeys ADR-039 — a repo-relative path fence, no
// directory creation, an in-memory strict re-parse by the verifier's own parser,
// and a temp-file + fsync + rename that fails closed and never leaves a partial
// live registry.
package enroll

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/semver-trust/semver-trust-go/internal/pathfence"
)

// registryMode is the file mode for registry files: public trust material, world-
// readable, owner-writable.
const registryMode = 0o644

// WriteRegistry persists content as the whole new contents of the policy-named
// registry at relPath under repoRoot, under the ADR-039 writer contract: relPath is
// fenced (reject-don't-sanitize — absolute, "..", or a symlink is refused), a
// missing parent directory is REFUSED with a hint (never MkdirAll'd), and the bytes
// are written to a temp file in the target's own directory, fsynced, and atomically
// renamed into place, with the containing directory fsynced for durability.
//
// content must already be the whole new registry, re-parsed by the caller with the
// verifier's strict parser — this function persists, it does not validate. An
// interrupted run leaves no partial live file: the rename is atomic, and the temp
// file is removed on any pre-rename error.
func WriteRegistry(repoRoot, relPath string, content []byte) error {
	abs, err := pathfence.Resolve(repoRoot, relPath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	// No MkdirAll on a missing parent: a missing parent is a refusal with a hint,
	// never a silent creation (ADR-039).
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("enroll: parent directory %q does not exist — create it and re-run (the tool never creates directories)", dir)
		}
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("enroll: %q is not a directory", dir)
	}

	tmp, err := os.CreateTemp(dir, ".enroll-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup: until the rename commits, an error path removes the temp
	// file so an interrupted run leaves nothing behind.
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, registryMode); err != nil {
		return err
	}
	if err := os.Rename(tmpName, abs); err != nil {
		return err
	}
	committed = true

	// fsync the directory so the rename itself is durable across a crash.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
