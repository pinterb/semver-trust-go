// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hex64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// writeDescriptor writes body to a fresh out-of-band directory (not the repo)
// and returns (descriptorPath, repoPath).
func writeDescriptor(t *testing.T, body string) (descriptorPath, repoPath string) {
	t.Helper()
	oob := t.TempDir()
	repo := t.TempDir()
	p := filepath.Join(oob, "bootstrap.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, repo
}

func inceptionBody() string {
	return `{
		"repository": "repo:test/auth",
		"component": "app",
		"interval_mode": "inception",
		"tag_prefix": "",
		"policy_path": ".semver-trust/policy.toml",
		"policy_digest": "sha256:` + hex64 + `",
		"verification_profile": "vp",
		"clock_profile": "cp",
		"version_predecessor": null,
		"trust_material": {"m/humans": "sha256:` + hex64 + `"},
		"trust_roles": {"human_signers": "m/humans"},
		"mandatory_meta_paths": ["ci/release"]
	}`
}

func TestLoadBootstrapInception(t *testing.T) {
	p, repo := writeDescriptor(t, inceptionBody())
	d, err := LoadBootstrapDescriptor(p, repo)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !d.Authenticated() {
		t.Error("descriptor should be authenticated after a valid out-of-band load")
	}
	vb := d.VersionBootstrap()
	if !vb.Authenticated || vb.Repository != "repo:test/auth" || vb.Component != "app" {
		t.Errorf("VersionBootstrap subject = %+v", vb)
	}
	if vb.IntervalMode != "inception" || vb.Boundary != nil {
		t.Errorf("inception should carry no boundary: %+v", vb)
	}
	if !vb.PredecessorPresent || !vb.PredecessorNull {
		t.Errorf("explicit null version_predecessor should be present and null: %+v", vb)
	}
}

func TestLoadBootstrapAdoptionWithPredecessor(t *testing.T) {
	body := `{
		"repository": "repo:test/auth",
		"component": "app",
		"interval_mode": "adoption",
		"boundary": {"oid": "` + hex64 + `", "ref_target": "` + hex64 + `"},
		"policy_path": ".semver-trust/policy.toml",
		"policy_digest": "sha256:` + hex64 + `",
		"verification_profile": "vp",
		"clock_profile": "cp",
		"version_predecessor": {"tag": "v1.4.0", "ref_oid": "` + hex64 + `", "commit_oid": "` + hex64 + `"}
	}`
	p, repo := writeDescriptor(t, body)
	d, err := LoadBootstrapDescriptor(p, repo)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	vb := d.VersionBootstrap()
	if vb.IntervalMode != "adoption" || vb.Boundary == nil || *vb.Boundary != hex64 {
		t.Errorf("adoption boundary = %+v", vb)
	}
	if !vb.PredecessorPresent || vb.PredecessorNull || vb.PredecessorAmbiguous {
		t.Errorf("binding predecessor should be present, non-null, non-ambiguous: %+v", vb)
	}
	if vb.Predecessor == nil || vb.Predecessor.Tag != "v1.4.0" {
		t.Errorf("predecessor binding = %+v", vb.Predecessor)
	}
}

func TestVersionPredecessorShapes(t *testing.T) {
	base := func(pred string) string {
		return `{
			"repository": "r", "component": "app", "interval_mode": "inception",
			"policy_path": "p", "policy_digest": "sha256:` + hex64 + `",
			"verification_profile": "vp", "clock_profile": "cp"` + pred + `}`
	}
	cases := []struct {
		name                          string
		pred                          string
		wantErr                       bool
		present, null, ambig, binding bool
	}{
		{name: "absent", pred: "", wantErr: true}, // genesis never infers a null line
		{name: "null", pred: `, "version_predecessor": null`, present: true, null: true},
		{name: "ambiguous list", pred: `, "version_predecessor": [{"tag":"a"},{"tag":"b"}]`, present: true, ambig: true},
		{name: "binding", pred: `, "version_predecessor": {"tag":"v1.0.0","ref_oid":"x","commit_oid":"y"}`, present: true, binding: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, repo := writeDescriptor(t, base(c.pred))
			d, err := LoadBootstrapDescriptor(p, repo)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected a validation error for an omitted version_predecessor")
				}
				return
			}
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			vb := d.VersionBootstrap()
			if vb.PredecessorPresent != c.present || vb.PredecessorNull != c.null ||
				vb.PredecessorAmbiguous != c.ambig || (vb.Predecessor != nil) != c.binding {
				t.Errorf("shape = present=%v null=%v ambig=%v binding=%v, want %v/%v/%v/%v",
					vb.PredecessorPresent, vb.PredecessorNull, vb.PredecessorAmbiguous, vb.Predecessor != nil,
					c.present, c.null, c.ambig, c.binding)
			}
		})
	}
}

func TestLoadBootstrapRejectsInsideRepo(t *testing.T) {
	repo := t.TempDir()
	sub := filepath.Join(repo, ".semver-trust")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(sub, "bootstrap.json")
	if err := os.WriteFile(p, []byte(inceptionBody()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBootstrapDescriptor(p, repo); err == nil || !strings.Contains(err.Error(), "out-of-band") {
		t.Fatalf("descriptor inside the repo must be rejected as not out-of-band, got %v", err)
	}
}

func TestLoadBootstrapValidation(t *testing.T) {
	valid := map[string]string{
		"repository": `"repo:test/auth"`, "component": `"app"`,
		"interval_mode": `"inception"`, "policy_path": `".semver-trust/policy.toml"`,
		"policy_digest": `"sha256:` + hex64 + `"`, "verification_profile": `"vp"`, "clock_profile": `"cp"`,
		"version_predecessor": `null`,
	}
	build := func(overrides map[string]string, drop ...string) string {
		m := map[string]string{}
		for k, v := range valid {
			m[k] = v
		}
		for k, v := range overrides {
			m[k] = v
		}
		for _, k := range drop {
			delete(m, k)
		}
		var parts []string
		for k, v := range m {
			parts = append(parts, `"`+k+`": `+v)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}

	cases := []struct {
		name string
		body string
	}{
		{"missing repository", build(nil, "repository")},
		{"missing version_predecessor", build(nil, "version_predecessor")},
		{"unknown interval mode", build(map[string]string{"interval_mode": `"sideways"`})},
		{"adoption without boundary", build(map[string]string{"interval_mode": `"adoption"`})},
		{"inception with boundary", build(map[string]string{"boundary": `{"oid":"x","ref_target":"y"}`})},
		{"malformed policy digest", build(map[string]string{"policy_digest": `"deadbeef"`})},
		{"malformed trust-material digest", build(map[string]string{"trust_material": `{"m/x": "nope"}`})},
		{"unknown field", build(map[string]string{"surprise": `"x"`})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, repo := writeDescriptor(t, c.body)
			if _, err := LoadBootstrapDescriptor(p, repo); err == nil {
				t.Errorf("expected a validation error for %s", c.name)
			}
		})
	}
}

func TestLoadBootstrapMissingFile(t *testing.T) {
	repo := t.TempDir()
	if _, err := LoadBootstrapDescriptor(filepath.Join(t.TempDir(), "nope.json"), repo); err == nil {
		t.Error("expected an error for a missing descriptor file")
	}
}

// TestLoadBootstrapRejectsExternalSymlinkIntoRepo proves the out-of-band guard
// canonicalizes symlinks: an external path that is a symlink to an in-repo
// descriptor must be rejected, not read as repository-controlled bytes.
func TestLoadBootstrapRejectsExternalSymlinkIntoRepo(t *testing.T) {
	repo := t.TempDir()
	oob := t.TempDir()
	inRepo := filepath.Join(repo, "bootstrap.json")
	if err := os.WriteFile(inRepo, []byte(inceptionBody()), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(oob, "bootstrap.json")
	if err := os.Symlink(inRepo, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := LoadBootstrapDescriptor(link, repo); err == nil || !strings.Contains(err.Error(), "out-of-band") {
		t.Fatalf("external symlink resolving into the repo must be rejected as not out-of-band, got %v", err)
	}
}
