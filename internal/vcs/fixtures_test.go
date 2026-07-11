// SPDX-License-Identifier: Apache-2.0

package vcs

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// buildFixtures runs scripts/build-fixtures.sh into a fresh temp directory and
// returns the two repository paths (no-tags, tagged). It is hermetic: the
// script builds local repositories with no network access, replacing the
// donor's live-GitHub clone (audit §5.8).
func buildFixtures(t *testing.T) (noTags, tagged string) {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file to find the fixture script")
	}
	script := filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts", "build-fixtures.sh")

	dest := t.TempDir()
	cmd := exec.Command("bash", script, dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-fixtures.sh failed: %v\n%s", err, out)
	}
	return filepath.Join(dest, "no-tags"), filepath.Join(dest, "tagged")
}
