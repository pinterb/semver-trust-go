// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const doctorPolicyTOML = `[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T3"
`

func doctorWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorCommand(t *testing.T) {
	repo := t.TempDir()
	gitCLI(t, repo, "init", "-q")
	gitCLI(t, repo, "config", "user.email", "alex@example.com")
	gitCLI(t, repo, "config", "user.name", "Alex")

	// No policy → policy/parse FAILs → doctor returns a non-nil error (exit 1),
	// and the run still prints the cannot-check footer + the verify invocation.
	out, _, err := runRoot(t, "doctor", "--repo", repo)
	if err == nil {
		t.Error("no policy: doctor should return a non-nil error (FAIL policy/parse)")
	}
	if !strings.Contains(out, "FAIL  policy/parse") {
		t.Errorf("want policy/parse FAIL:\n%s", out)
	}
	if !strings.Contains(out, "cannot check") {
		t.Error("doctor must print the cannot-check footer")
	}
	if !strings.Contains(out, "semver-trust verify --repo") {
		t.Error("doctor must end by printing the verify invocation")
	}

	// A minimal valid, committed policy → policy/parse PASSes.
	doctorWriteFile(t, filepath.Join(repo, ".semver-trust", "policy.toml"), doctorPolicyTOML)
	gitCLI(t, repo, "add", ".")
	gitCLI(t, repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "policy")
	out2, _, _ := runRoot(t, "doctor", "--repo", repo)
	if !strings.Contains(out2, "PASS  policy/parse") {
		t.Errorf("a valid committed policy should PASS policy/parse:\n%s", out2)
	}

	// --json emits a structured report keyed by check id.
	jout, _, _ := runRoot(t, "doctor", "--repo", repo, "--json")
	if !strings.Contains(jout, `"id": "policy/parse"`) || !strings.Contains(jout, `"severity":`) {
		t.Errorf("json report shape:\n%s", jout)
	}

	// --persona agent is accepted and disclosed.
	aout, _, _ := runRoot(t, "doctor", "--repo", repo, "--persona", "agent")
	if !strings.Contains(aout, "persona: agent") {
		t.Errorf("persona agent header:\n%s", aout)
	}
	// An unknown persona errors out.
	if _, _, err := runRoot(t, "doctor", "--repo", repo, "--persona", "bogus"); err == nil {
		t.Error("unknown --persona should error")
	}

	// A traversing --policy path is refused by the fence before any read: doctor
	// must not read outside the repository even for a read-only diagnostic (ADR-039).
	fout, _, ferr := runRoot(t, "doctor", "--repo", repo, "--policy", "../../../../etc/passwd")
	if ferr == nil {
		t.Error("a traversing --policy path should FAIL (fence refusal), not read outside the repo")
	}
	if !strings.Contains(fout, "pathfence") {
		t.Errorf("a traversing --policy path should surface the fence refusal:\n%s", fout)
	}

	// A present-but-unreadable policy path (here, a directory) surfaces the read
	// error, not the generic "no policy at …" message.
	dout, _, derr := runRoot(t, "doctor", "--repo", repo, "--policy", ".semver-trust")
	if derr == nil {
		t.Error("--policy pointing at a directory should FAIL")
	}
	if !strings.Contains(dout, "could not be loaded") || strings.Contains(dout, "no policy at") {
		t.Errorf("a directory policy path should surface the read error, not \"no policy\":\n%s", dout)
	}

	// --message - reads the commit message from stdin (the documented contract).
	root := newRootCmd()
	var mout, merr bytes.Buffer
	root.SetOut(&mout)
	root.SetErr(&merr)
	root.SetIn(strings.NewReader("subject\n\nProvenance: human\n"))
	root.SetArgs([]string{"doctor", "--repo", repo, "--message", "-"})
	_ = root.Execute()
	if !strings.Contains(mout.String(), "simulate/classify") || !strings.Contains(mout.String(), "Provenance: human") {
		t.Errorf("--message - should classify the stdin message:\n%s", mout.String())
	}
}
