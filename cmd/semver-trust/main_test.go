// SPDX-License-Identifier: Apache-2.0

package main

import (
	"regexp"
	"testing"
)

// The --version output is the acceptance surface for the GO-026 pin: the
// spec draft version and source commit come from the vendored manifest, the
// single pin location.
func TestVersionString(t *testing.T) {
	got := versionString()
	want := regexp.MustCompile(
		`^semver-trust \S+\nconformance: SemVer-Trust spec draft v[0-9]+\.[0-9]+ vectors ` +
			`\(github\.com/semver-trust/spec@[0-9a-f]{12}\)$`,
	)
	if !want.MatchString(got) {
		t.Errorf("versionString() = %q, want match for %s", got, want)
	}
}
