// SPDX-License-Identifier: Apache-2.0

package vcs

import "testing"

// TestGitSSHNamespace pins the exported commit/tag signing namespace. It is
// exported (unlike the former unexported gitSSHNamespace) so out-of-package
// tooling — enroll/doctor (the bootstrap family) — can name the namespace that
// makes a commit-signing enrollment line count, without duplicating the literal.
func TestGitSSHNamespace(t *testing.T) {
	if GitSSHNamespace != "git" {
		t.Errorf("GitSSHNamespace = %q, want %q", GitSSHNamespace, "git")
	}
}
