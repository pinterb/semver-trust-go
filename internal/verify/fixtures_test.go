// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// cryptoVendorDir locates the ADR-021 vendored crypto fixtures relative to
// this test source file, mirroring the vcs conformance test.
func cryptoVendorDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "vendor", "crypto")
}

// allowedSignersPath is the vendored commit-signing registry used as the
// --allowed-signers override for fixtures whose policy declares no in-tree path.
func allowedSignersPath(t *testing.T) string {
	return filepath.Join(cryptoVendorDir(t), "allowed_signers")
}

// buildFixtures runs the vendored deterministic builder once into a temp dir.
// Hermetic: local repositories, no network.
func buildFixtures(t *testing.T) string {
	t.Helper()
	dest := t.TempDir()
	script := filepath.Join(cryptoVendorDir(t), "build-fixture-repos.sh")
	cmd := exec.Command("bash", script, dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-fixture-repos.sh failed: %v\n%s", err, out)
	}
	return dest
}
