// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConformancePublishingProfile drives the spec's publishing-profile vectors
// (§7.4, ADR-034) through SelectPublishingProfile: registry routing is not a
// trust anchor, same-source promotion proves artifact equality only under a
// reproducible-build profile, and each ecosystem's default resolution must hide
// or defer a trust pre-release, each mismatch aborting with a stable reason.
func TestConformancePublishingProfile(t *testing.T) {
	doc := loadPublishingProfileVectors(t)
	seen := 0
	for _, vec := range doc.Vectors {
		if vec.Kind != "publishing_profile" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			accepted, reason := SelectPublishingProfile(vec.Inputs.build())
			if accepted != vec.Expected.Accepted {
				t.Errorf("accepted = %v (reason %q), want %v (reason %q)", accepted, reason, vec.Expected.Accepted, ptrStr(vec.Expected.Reason))
			}
			if reason != ptrStr(vec.Expected.Reason) {
				t.Errorf("reason = %q, want %q", reason, ptrStr(vec.Expected.Reason))
			}
		})
	}
	if seen == 0 {
		t.Fatal("no publishing_profile vectors ran")
	}
}

func ptrStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

type ppInputs struct {
	Claim                    string            `json:"claim"`
	Ecosystem                string            `json:"ecosystem"`
	RegistryVersions         []string          `json:"registry_versions"`
	AttestationVerified      bool              `json:"attestation_verified"`
	SourceRevision           string            `json:"source_revision"`
	PromotedSourceRevision   string            `json:"promoted_source_revision"`
	ReproducibleBuildProfile json.RawMessage   `json:"reproducible_build_profile"`
	ArtifactDigest           string            `json:"artifact_digest"`
	PromotedArtifactDigest   string            `json:"promoted_artifact_digest"`
	DistTags                 map[string]string `json:"dist_tags"`
	OrdinaryInstallIntended  bool              `json:"ordinary_install_intended"`
	ProjectedFrom            []string          `json:"projected_from"`
}

func (in ppInputs) build() PublishInputs {
	return PublishInputs{
		Claim: in.Claim, Ecosystem: in.Ecosystem, RegistryVersions: in.RegistryVersions,
		AttestationVerified: in.AttestationVerified, SourceRevision: in.SourceRevision,
		PromotedSourceRevision:      in.PromotedSourceRevision,
		HasReproducibleBuildProfile: hasProfile(in.ReproducibleBuildProfile),
		ArtifactDigest:              in.ArtifactDigest, PromotedArtifactDigest: in.PromotedArtifactDigest,
		DistTagLatest: in.DistTags["latest"], OrdinaryInstallIntended: in.OrdinaryInstallIntended,
		ProjectedFrom: in.ProjectedFrom,
	}
}

// hasProfile mirrors the oracle's `reproducible_build_profile is None` gate:
// absent or JSON null is false, any other value is present.
func hasProfile(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

type ppVector struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Inputs   ppInputs `json:"inputs"`
	Expected struct {
		Accepted bool    `json:"accepted"`
		Reason   *string `json:"reason"`
	} `json:"expected"`
}

type ppDoc struct {
	SpecVersion string     `json:"spec_version"`
	Vectors     []ppVector `json:"vectors"`
}

func loadPublishingProfileVectors(t *testing.T) ppDoc {
	t.Helper()
	const name = "publishing-profile.json"
	path := os.Getenv("SEMVER_TRUST_PUBLISHING_PROFILE_VECTORS")
	if path == "" {
		for _, candidate := range []string{
			filepath.Join("testdata", name),
			filepath.Join("..", "..", "conformance", "vendor", name),
		} {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		t.Fatalf("conformance vectors absent: conformance/vendor/%s missing (refresh via scripts/sync-conformance.py)", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading vectors %q: %v", path, err)
	}
	var doc ppDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing vectors %q: %v", path, err)
	}
	return doc
}
