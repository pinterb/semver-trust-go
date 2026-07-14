// SPDX-License-Identifier: Apache-2.0

package publish

import "testing"

// ppEqualityBase is a valid same_source_promotion_proves_artifact_equality
// claim: identical source revision, a reproducible-build profile present, and
// equal artifact digests.
func ppEqualityBase() PublishInputs {
	return PublishInputs{
		Claim:                       "same_source_promotion_proves_artifact_equality",
		Ecosystem:                   "npm",
		SourceRevision:              "cccccccccccccccccccccccccccccccccccccccc",
		PromotedSourceRevision:      "cccccccccccccccccccccccccccccccccccccccc",
		HasReproducibleBuildProfile: true,
		ArtifactDigest:              "sha256:aaaa",
		PromotedArtifactDigest:      "sha256:aaaa",
	}
}

// TestSelectPublishingProfileOracleSurface pins the ADR-034 outcomes the
// vendored vectors do not exercise: source_identity_mismatch on both promotion
// claims, artifact_digest_mismatch, unsupported_profile_claim (unknown claim
// and claim/ecosystem mismatch), and the artifact-equality accept path — so the
// port mirrors the oracle's full decision surface.
func TestSelectPublishingProfileOracleSurface(t *testing.T) {
	if ok, r := SelectPublishingProfile(ppEqualityBase()); !ok || r != "" {
		t.Fatalf("equality base = (%v,%q), want accepted", ok, r)
	}

	cases := []struct {
		name   string
		in     func() PublishInputs
		wantOK bool
		want   string
	}{
		{"artifact equality proven accepts", ppEqualityBase, true, ""},
		{"equality claim, source revision differs", func() PublishInputs {
			in := ppEqualityBase()
			in.PromotedSourceRevision = "dddddddddddddddddddddddddddddddddddddddd"
			return in
		}, false, "source_identity_mismatch"},
		{"plain promotion, source revision differs", func() PublishInputs {
			in := ppEqualityBase()
			in.Claim = "same_source_promotion"
			in.PromotedSourceRevision = "dddddddddddddddddddddddddddddddddddddddd"
			return in
		}, false, "source_identity_mismatch"},
		{"equality claim, artifact digest differs", func() PublishInputs {
			in := ppEqualityBase()
			in.PromotedArtifactDigest = "sha256:bbbb"
			return in
		}, false, "artifact_digest_mismatch"},
		{"unknown claim", func() PublishInputs {
			in := ppEqualityBase()
			in.Claim = "registry_routing_is_magic"
			return in
		}, false, "unsupported_profile_claim"},
		{"go claim under npm ecosystem", func() PublishInputs {
			return PublishInputs{
				Ecosystem: "npm", Claim: "default_query_hides_trust_prerelease",
				RegistryVersions: []string{"1.4.1-t1.1"},
			}
		}, false, "unsupported_profile_claim"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, r := SelectPublishingProfile(c.in())
			if ok != c.wantOK || r != c.want {
				t.Errorf("= (%v,%q), want (%v,%q)", ok, r, c.wantOK, c.want)
			}
		})
	}
}
