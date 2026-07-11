// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/verify"
)

// The cobra `verify --json` path is the CLI's acceptance surface: it drives the
// pipeline and emits the structured report. Golden-ish assertions on key
// fields (not a brittle full-golden) confirm the wiring end-to-end.
func TestVerifyJSONCommand(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "release")

	var out, errBuf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs([]string{
		"verify",
		"--repo", repo,
		"--from", "v0.1.0",
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--verify-time", "2026-01-01T00:00:00Z",
		"--json",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("verify --json: %v\nstderr: %s", err, errBuf.String())
	}

	var report verify.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decoding JSON report: %v\n%s", err, out.String())
	}
	if len(report.Commits) != 2 {
		t.Errorf("commits = %d, want 2", len(report.Commits))
	}
	if report.Policy.Digest == "" {
		t.Error("policy digest empty")
	}
	if !report.MetaPath.Passed {
		t.Error("meta-path check not passed")
	}
	if len(report.Scopes) != 1 || report.Scopes[0].OwnFloor != "T0" {
		t.Errorf("scopes = %+v, want a single default scope floored to T0", report.Scopes)
	}
}

// A verification abort surfaces as a non-zero exit: Execute returns an error
// (main maps it to os.Exit(1)), and the reason names the §10 step on stderr.
func TestVerifyAbortReturnsError(t *testing.T) {
	repo := filepath.Join(buildFixtures(t), "signed-history") // no policy in tree

	var out, errBuf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs([]string{
		"verify",
		"--repo", repo,
		"--to", "main",
		"--allowed-signers", allowedSignersPath(t),
		"--verify-time", "2026-01-01T00:00:00Z",
	})
	if err := root.Execute(); err == nil {
		t.Fatal("Execute returned nil, want an abort error")
	}
	if !bytes.Contains(errBuf.Bytes(), []byte("§10 step 1")) {
		t.Errorf("stderr = %q, want it to name §10 step 1", errBuf.String())
	}
}

func cryptoVendorDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "conformance", "vendor", "crypto")
}

func allowedSignersPath(t *testing.T) string {
	return filepath.Join(cryptoVendorDir(t), "allowed_signers")
}

func buildFixtures(t *testing.T) string {
	t.Helper()
	dest := t.TempDir()
	script := filepath.Join(cryptoVendorDir(t), "build-fixture-repos.sh")
	if out, err := exec.Command("bash", script, dest).CombinedOutput(); err != nil {
		t.Fatalf("build-fixture-repos.sh failed: %v\n%s", err, out)
	}
	return dest
}
