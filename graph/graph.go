// SPDX-License-Identifier: Apache-2.0

// Package graph is the public workspace-graph adapter seam (spec §5.3,
// ADR-011): adapters resolve the internal dependency graph of a workspace —
// which first-party components exist and which consume which — so effective
// trust can propagate as a floor over it. External (third-party)
// dependencies are out of scope for effective-trust computation (§1.2).
//
// This package is one of the three seams deliberately kept public (evidence
// providers, workspace graph adapters, registry projections); everything
// else in this module lives under internal/.
package graph

// Component is a workspace-internal unit of release: the name components are
// known by (which doubles as the §7.1 component-path tag prefix, e.g.
// "pkg/common") and the directory that roots it, relative to the workspace
// root in slash form. The workspace root itself has Dir ".".
type Component struct {
	Name string
	Dir  string
}

// Graph is a workspace's internal dependency graph. Edges point
// consumer → dependency, by component name, and reference only components
// present in Components.
type Graph struct {
	Components []Component
	Edges      [][2]string
}

// Adapter resolves the internal dependency graph for one workspace tooling
// ecosystem (Go module graph, pnpm/npm workspaces, Cargo workspace metadata,
// Bazel query, …). Implementations read the workspace's own manifests; they
// MUST NOT fetch anything over the network (ADR-018 posture: verification
// consumes injected, local state).
type Adapter interface {
	// Name is the adapter's policy-facing name (§9 [graph] adapter).
	Name() string

	// Resolve builds the graph for the workspace rooted at dir, evaluated at
	// the tree state currently on disk — the version actually consumed by
	// the release being cut (§5.3).
	Resolve(dir string) (Graph, error)
}
