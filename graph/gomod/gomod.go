// SPDX-License-Identifier: Apache-2.0

// Package gomod is the Go-workspace graph adapter (spec §5.3, §9
// adapter = "gomod"): components are the workspace's nested Go modules —
// the layout whose dir/vX.Y.Z tag convention the §7.1 component-path prefix
// mirrors — and edges come from require and local replace directives that
// resolve to sibling modules in the same workspace.
//
// Resolution is purely lexical: go.mod files are parsed with
// golang.org/x/mod/modfile, nothing is executed and nothing is fetched. A
// require edge is internal when the required module path is another
// workspace module's path, or when a replace directive redirects it to a
// local directory inside the workspace.
package gomod

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/semver-trust/semver-trust-go/graph"
)

// Adapter resolves Go module workspaces. The zero value is ready to use.
type Adapter struct{}

// Name returns the §9 policy vocabulary name for this adapter.
func (Adapter) Name() string { return "gomod" }

// module is one parsed go.mod: where it lives and what it requires.
type module struct {
	dir      string // slash-form, relative to the workspace root; "." for the root
	path     string // module path
	requires []string
	replaces map[string]string // module path -> replacement (path or local dir)
}

// Resolve walks dir for go.mod files (skipping VCS metadata, vendor trees,
// and testdata), names each module by its directory, and derives edges from
// requires resolving to sibling modules.
func (Adapter) Resolve(dir string) (graph.Graph, error) {
	modules, err := discover(dir)
	if err != nil {
		return graph.Graph{}, err
	}
	if len(modules) == 0 {
		return graph.Graph{}, fmt.Errorf("gomod: no go.mod found under %s", dir)
	}

	byPath := map[string]*module{}
	byDir := map[string]*module{}
	for _, m := range modules {
		if other, dup := byPath[m.path]; dup {
			return graph.Graph{}, fmt.Errorf("gomod: module path %s declared by both %s and %s", m.path, other.dir, m.dir)
		}
		byPath[m.path] = m
		byDir[m.dir] = m
	}

	g := graph.Graph{}
	for _, m := range modules {
		g.Components = append(g.Components, graph.Component{Name: m.dir, Dir: m.dir})
	}

	seen := map[[2]string]bool{}
	for _, m := range modules {
		for _, req := range m.requires {
			dep := resolveInternal(m, req, byPath, byDir)
			if dep == nil || dep == m {
				continue
			}
			edge := [2]string{m.dir, dep.dir}
			if !seen[edge] {
				seen[edge] = true
				g.Edges = append(g.Edges, edge)
			}
		}
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i][0] != g.Edges[j][0] {
			return g.Edges[i][0] < g.Edges[j][0]
		}
		return g.Edges[i][1] < g.Edges[j][1]
	})
	return g, nil
}

// resolveInternal decides whether a required module path is another module
// of the same workspace: directly by path, or through a replace directive
// pointing at a local workspace directory.
func resolveInternal(m *module, req string, byPath map[string]*module, byDir map[string]*module) *module {
	if repl, ok := m.replaces[req]; ok {
		if strings.HasPrefix(repl, "./") || strings.HasPrefix(repl, "../") {
			target := filepath.ToSlash(filepath.Join(m.dir, repl))
			return byDir[target]
		}
		return byPath[repl]
	}
	return byPath[req]
}

func discover(root string) ([]*module, error) {
	var modules []*module
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mf, err := modfile.Parse(path, data, nil)
		if err != nil {
			return fmt.Errorf("gomod: parsing %s: %w", path, err)
		}
		if mf.Module == nil {
			return fmt.Errorf("gomod: %s has no module directive", path)
		}

		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		m := &module{
			dir:      filepath.ToSlash(rel),
			path:     mf.Module.Mod.Path,
			replaces: map[string]string{},
		}
		for _, r := range mf.Require {
			m.requires = append(m.requires, r.Mod.Path)
		}
		for _, r := range mf.Replace {
			m.replaces[r.Old.Path] = r.New.Path
		}
		modules = append(modules, m)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].dir < modules[j].dir })
	return modules, nil
}
