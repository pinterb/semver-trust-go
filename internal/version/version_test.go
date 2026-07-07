// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

func TestVersionString(t *testing.T) {
	tests := []struct {
		v    Version
		want string
	}{
		{Version{Major: 1, Minor: 0, Patch: 0}, "v1.0.0"},
		{Version{Component: "auth", Major: 2, Minor: 1, Patch: 3}, "auth/v2.1.3"},
		{Version{Major: 1, Minor: 4, Patch: 0, Trust: &TrustSuffix{Level: 1, Iteration: 1}}, "v1.4.0-t1.1"},
		{Version{Component: "pkg/common", Major: 0, Minor: 9, Patch: 0, Trust: &TrustSuffix{Level: 0, Iteration: 3}}, "pkg/common/v0.9.0-t0.3"},
		{Version{Major: 1, Minor: 4, Patch: 0, Pre: []string{"rc", "1"}}, "v1.4.0-rc.1"},
	}
	for _, tc := range tests {
		if got := tc.v.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

func TestVersionKind(t *testing.T) {
	tests := []struct {
		v    Version
		want Kind
	}{
		{Version{Major: 1}, KindTrust},                                              // clean
		{Version{Major: 1, Trust: &TrustSuffix{Level: 2, Iteration: 1}}, KindTrust}, // trust-suffixed
		{Version{Major: 1, Pre: []string{"rc", "1"}}, KindPlain},                    // plain pre-release
	}
	for _, tc := range tests {
		if got := tc.v.Kind(); got != tc.want {
			t.Errorf("Kind(%s) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

func TestKindString(t *testing.T) {
	if got := KindTrust.String(); got != "trust_version" {
		t.Errorf("KindTrust.String() = %q", got)
	}
	if got := KindPlain.String(); got != "plain_version" {
		t.Errorf("KindPlain.String() = %q", got)
	}
}
