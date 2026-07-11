// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	iofs "io/fs"
	"regexp"
	"strings"
	"testing"
)

// TestVendoredBytesMatchManifest is the ADR-021 drift check: every vendored
// file's bytes must hash to the digest the manifest pins, every manifest
// entry must have its file, and no unlisted file may hide in vendor/.
// Everyone verifies the same bytes; refreshing goes through
// scripts/sync-conformance.py, never by hand.
func TestVendoredBytesMatchManifest(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for name, want := range m.Files {
		data, err := fs.ReadFile("vendor/" + name)
		if err != nil {
			t.Errorf("manifest lists %s but it is not vendored: %v", name, err)
			continue
		}
		sum := sha256.Sum256(data)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: vendored bytes hash to %s, manifest pins %s — refresh via scripts/sync-conformance.py", name, got, want)
		}
	}

	err = iofs.WalkDir(fs, "vendor", func(path string, d iofs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if _, listed := m.Files[strings.TrimPrefix(path, "vendor/")]; !listed {
			t.Errorf("%s is not listed in the manifest", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestManifestPin pins the manifest's own shape: a full-length source
// commit, a plausible spec version, digests in sha256:<hex> form, and the
// vendored LICENSE so copies stay self-describing (ADR-014/ADR-021).
func TestManifestPin(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(m.Source.Commit) {
		t.Errorf("source commit %q is not a full 40-char sha", m.Source.Commit)
	}
	if m.Source.Repository != "https://github.com/semver-trust/spec" {
		t.Errorf("source repository = %q", m.Source.Repository)
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(m.SpecVersion) {
		t.Errorf("spec_version %q is not MAJOR.MINOR", m.SpecVersion)
	}
	digest := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	for name, d := range m.Files {
		if !digest.MatchString(d) {
			t.Errorf("%s: malformed digest %q", name, d)
		}
	}
	if _, ok := m.Files["LICENSE"]; !ok {
		t.Error("vendored LICENSE missing from the manifest")
	}

	// Every vector file (a JSON document carrying a vectors array) pins the
	// same spec_version as the manifest. Other vendored JSON — DSSE
	// envelopes, the predicate schemas — legitimately carries none.
	vectorFiles := 0
	for name := range m.Files {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		data, err := Vector(name)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			SpecVersion string          `json:"spec_version"`
			Vectors     json.RawMessage `json:"vectors"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if doc.Vectors == nil {
			continue
		}
		vectorFiles++
		if doc.SpecVersion != m.SpecVersion {
			t.Errorf("%s pins spec_version %q, manifest pins %q", name, doc.SpecVersion, m.SpecVersion)
		}
	}
	if vectorFiles < 7 {
		t.Errorf("only %d vector files found in the manifest; expected at least 7", vectorFiles)
	}
}

func TestAccessors(t *testing.T) {
	if got := SpecVersion(); got == "unknown" || got == "" {
		t.Errorf("SpecVersion() = %q", got)
	}
	if got := SourceCommit(); len(got) != 40 {
		t.Errorf("SourceCommit() = %q", got)
	}
	if _, err := Vector("levels.json"); err != nil {
		t.Errorf("Vector(levels.json): %v", err)
	}
}
