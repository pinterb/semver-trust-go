// SPDX-License-Identifier: Apache-2.0

package apidiff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/semver-trust/semver-trust-go/evidence"
)

// writeTree lays a one-package module out in a temp dir. Hermetic: the
// module has no requirements, so loading resolves nothing beyond the local
// tree and the standard library.
func writeTree(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/fixture\n\ngo 1.26\n",
		"x.go":   source,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const oldSource = `package x

// Greet returns a greeting for name.
func Greet(name string) string { return "hello " + name }

// Version is the fixture's public constant.
const Version = 1
`

func TestFloor(t *testing.T) {
	tests := []struct {
		name string
		new  string
		want evidence.Bump
	}{
		{
			name: "unchanged public surface permits a patch",
			new:  oldSource,
			want: evidence.BumpPatch,
		},
		{
			name: "internal-only change permits a patch",
			new: `package x

func Greet(name string) string { return "hi " + name }

const Version = 1
`,
			want: evidence.BumpPatch,
		},
		{
			name: "additive change forces a minor",
			new: oldSource + `
// Farewell is new exported API.
func Farewell(name string) string { return "bye " + name }
`,
			want: evidence.BumpMinor,
		},
		{
			name: "signature change forces a major",
			new: `package x

func Greet(name string, formal bool) string { return "hello " + name }

const Version = 1
`,
			want: evidence.BumpMajor,
		},
		{
			name: "removed API forces a major",
			new: `package x

const Version = 1
`,
			want: evidence.BumpMajor,
		},
	}

	old := writeTree(t, oldSource)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (Differ{}).Floor(old, writeTree(t, tt.new))
			if err != nil {
				t.Fatalf("Floor: %v", err)
			}
			if got != tt.want {
				t.Errorf("Floor = %s, want %s", got, tt.want)
			}
		})
	}
}

// A tree that does not typecheck yields an error, never a floor — the differ
// fails closed.
func TestFloorFailsClosed(t *testing.T) {
	old := writeTree(t, oldSource)
	broken := writeTree(t, "package x\n\nfunc Greet( {\n")
	if _, err := (Differ{}).Floor(old, broken); err == nil {
		t.Error("Floor accepted a tree that does not typecheck")
	}
}

func TestDifferName(t *testing.T) {
	if got := (Differ{}).Name(); got != "apidiff" {
		t.Errorf("Name() = %q, want %q", got, "apidiff")
	}
}

// The differ satisfies the public seam.
var _ evidence.CompatDiffer = Differ{}
