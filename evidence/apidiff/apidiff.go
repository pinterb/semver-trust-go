// SPDX-License-Identifier: Apache-2.0

// Package apidiff is the Go compatibility differ (spec §6.1, §9
// [evidence.go] compat = "apidiff"): it compares the exported API of the
// package rooted at two trees via golang.org/x/exp/apidiff and reports the
// semantic floor — any incompatible change forces BumpMajor, compatible
// changes force BumpMinor, an unchanged public surface permits BumpPatch.
//
// This first provider diffs one package per component: the package at the
// component's root directory. Whole-workspace aggregation across packages
// composes at the release-evaluation layer, which takes the maximum floor
// over the differs it runs. Loading uses the local toolchain's view of the
// tree (nothing is fetched: the loader runs with GOPROXY=off) and fails
// closed — a tree that does not typecheck yields an error, never a floor.
package apidiff

import (
	"fmt"
	"go/types"
	"os"

	"golang.org/x/exp/apidiff"
	"golang.org/x/tools/go/packages"

	"github.com/semver-trust/semver-trust-go/evidence"
)

// Differ implements evidence.CompatDiffer for Go. The zero value is ready to
// use.
type Differ struct{}

// Name returns the §9 policy vocabulary name for this differ.
func (Differ) Name() string { return "apidiff" }

// Floor compares the package rooted at oldDir against the one rooted at
// newDir (§6.1).
func (Differ) Floor(oldDir, newDir string) (evidence.Bump, error) {
	oldPkg, err := load(oldDir)
	if err != nil {
		return 0, fmt.Errorf("apidiff: old tree: %w", err)
	}
	newPkg, err := load(newDir)
	if err != nil {
		return 0, fmt.Errorf("apidiff: new tree: %w", err)
	}

	report := apidiff.Changes(oldPkg, newPkg)
	floor := evidence.BumpPatch
	for _, change := range report.Changes {
		if !change.Compatible {
			return evidence.BumpMajor, nil
		}
		floor = evidence.BumpMinor
	}
	return floor, nil
}

func load(dir string) (*types.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedTypesInfo |
			packages.NeedSyntax | packages.NeedImports | packages.NeedDeps,
		Dir: dir,
		// Fail closed and stay hermetic: resolve from the local tree and
		// module cache only.
		Env: append(os.Environ(), "GOPROXY=off", "GOWORK=off", "GOFLAGS=-mod=mod"),
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		return nil, err
	}
	if len(pkgs) != 1 {
		return nil, fmt.Errorf("expected one package at %s, found %d", dir, len(pkgs))
	}
	if len(pkgs[0].Errors) > 0 {
		return nil, fmt.Errorf("loading %s: %v", dir, pkgs[0].Errors[0])
	}
	return pkgs[0].Types, nil
}
