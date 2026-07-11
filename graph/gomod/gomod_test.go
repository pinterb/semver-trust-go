// SPDX-License-Identifier: Apache-2.0

package gomod

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/semver-trust/semver-trust-go/graph"
)

// write lays a workspace out in a temp dir from a map of relative path →
// contents. Hermetic: plain files, no git, no network.
func write(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestResolveAppendixAShape(t *testing.T) {
	// The Appendix A workspace: both services depend on pkg/common.
	root := write(t, map[string]string{
		"go.mod": "module example.com/platform\n\ngo 1.26\n",
		"pkg/common/go.mod": "module example.com/platform/pkg/common\n\ngo 1.26\n",
		"services/auth/go.mod": "module example.com/platform/services/auth\n\ngo 1.26\n\n" +
			"require example.com/platform/pkg/common v0.9.0\n",
		"services/billing/go.mod": "module example.com/platform/services/billing\n\ngo 1.26\n\n" +
			"require (\n\texample.com/platform/pkg/common v0.9.0\n\tgolang.org/x/mod v0.30.0\n)\n",
	})

	g, err := Adapter{}.Resolve(root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	wantComponents := []graph.Component{
		{Name: ".", Dir: "."},
		{Name: "pkg/common", Dir: "pkg/common"},
		{Name: "services/auth", Dir: "services/auth"},
		{Name: "services/billing", Dir: "services/billing"},
	}
	if !reflect.DeepEqual(g.Components, wantComponents) {
		t.Errorf("components = %v, want %v", g.Components, wantComponents)
	}

	// External requires (x/mod) contribute no edge (§1.2: third-party deps
	// are out of scope for effective trust).
	wantEdges := [][2]string{
		{"services/auth", "pkg/common"},
		{"services/billing", "pkg/common"},
	}
	if !reflect.DeepEqual(g.Edges, wantEdges) {
		t.Errorf("edges = %v, want %v", g.Edges, wantEdges)
	}
}

func TestResolveLocalReplace(t *testing.T) {
	// A require of an external path replaced by a local sibling directory is
	// an internal edge — the tree consumed is the workspace's own.
	root := write(t, map[string]string{
		"lib/go.mod": "module example.com/lib\n\ngo 1.26\n",
		"app/go.mod": "module example.com/app\n\ngo 1.26\n\n" +
			"require example.com/lib v1.0.0\n\n" +
			"replace example.com/lib => ../lib\n",
	})

	g, err := Adapter{}.Resolve(root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	wantEdges := [][2]string{{"app", "lib"}}
	if !reflect.DeepEqual(g.Edges, wantEdges) {
		t.Errorf("edges = %v, want %v", g.Edges, wantEdges)
	}
}

func TestResolveReplaceRedirectsOutside(t *testing.T) {
	// A replace pointing outside the workspace removes the edge: the tree
	// consumed is not a workspace component.
	root := write(t, map[string]string{
		"lib/go.mod": "module example.com/lib\n\ngo 1.26\n",
		"app/go.mod": "module example.com/app\n\ngo 1.26\n\n" +
			"require example.com/lib v1.0.0\n\n" +
			"replace example.com/lib => example.com/fork v1.0.1\n",
	})

	g, err := Adapter{}.Resolve(root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(g.Edges) != 0 {
		t.Errorf("edges = %v, want none", g.Edges)
	}
}

func TestResolveSkipsVendorAndTestdata(t *testing.T) {
	root := write(t, map[string]string{
		"go.mod":                "module example.com/app\n\ngo 1.26\n",
		"vendor/dep/go.mod":     "module example.com/vendored\n\ngo 1.26\n",
		"testdata/fixture/go.mod": "module example.com/fixture\n\ngo 1.26\n",
	})

	g, err := Adapter{}.Resolve(root)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(g.Components) != 1 || g.Components[0].Name != "." {
		t.Errorf("components = %v, want only the root module", g.Components)
	}
}

func TestResolveErrors(t *testing.T) {
	t.Run("no modules", func(t *testing.T) {
		if _, err := (Adapter{}).Resolve(t.TempDir()); err == nil {
			t.Error("Resolve accepted a workspace with no go.mod")
		}
	})
	t.Run("duplicate module path", func(t *testing.T) {
		root := write(t, map[string]string{
			"a/go.mod": "module example.com/dup\n\ngo 1.26\n",
			"b/go.mod": "module example.com/dup\n\ngo 1.26\n",
		})
		if _, err := (Adapter{}).Resolve(root); err == nil {
			t.Error("Resolve accepted duplicate module paths")
		}
	})
	t.Run("malformed go.mod", func(t *testing.T) {
		root := write(t, map[string]string{"go.mod": "not a modfile\n"})
		if _, err := (Adapter{}).Resolve(root); err == nil {
			t.Error("Resolve accepted a malformed go.mod")
		}
	})
}

func TestAdapterName(t *testing.T) {
	if got := (Adapter{}).Name(); got != "gomod" {
		t.Errorf("Name() = %q, want %q", got, "gomod")
	}
}

// The adapter satisfies the public seam.
var _ graph.Adapter = Adapter{}
