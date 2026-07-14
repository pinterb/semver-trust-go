// SPDX-License-Identifier: Apache-2.0

// Package publish evaluates ecosystem publishing profiles (§7.4, ADR-034):
// resolver-routing claims are constrained so a registry's default-resolution
// behavior is never mistaken for a trust anchor. Each ecosystem (go, npm,
// cargo, pypi) has a bounded set of claims about how it hides or projects a
// trust pre-release, and same-source promotion may assert artifact equality
// only under a reproducible-build profile with matching digests.
package publish

import "regexp"

// A trust pre-release identifier (§7.1) appearing anywhere in a version string:
// t{0..3}.{iteration>=1}, at the start or after '-', ending at end or before
// build metadata.
var trustPrereleaseRe = regexp.MustCompile(`(?:^|-)t[0-3]\.[1-9][0-9]*(?:$|\+)`)

// A bare SemVer version (no tag prefix), used to detect a release (non-pre)
// version among registry versions.
var semverRe = regexp.MustCompile(
	`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)` +
		`(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// The §7.1 strict trust-tag grammar: optional path, v<core>, optional trust
// suffix. Groups: 1=path, 2=core, 3=level, 4=iter.
var trustTagRe = regexp.MustCompile(
	`^(?:[0-9A-Za-z._-]+(?:/[0-9A-Za-z._-]+)*/)?` +
		`v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))` +
		`(?:-t([0-3])\.([1-9][0-9]*))?$`)

// PublishInputs are the facts an ecosystem publishing-profile claim is
// evaluated against (§7.4, ADR-034). HasReproducibleBuildProfile records only
// whether a reproducible-build profile is present, and DistTagLatest is the
// npm "latest" dist-tag ("" when absent).
type PublishInputs struct {
	Claim                       string
	Ecosystem                   string
	RegistryVersions            []string
	AttestationVerified         bool
	SourceRevision              string
	PromotedSourceRevision      string
	HasReproducibleBuildProfile bool
	ArtifactDigest              string
	PromotedArtifactDigest      string
	DistTagLatest               string
	OrdinaryInstallIntended     bool
	ProjectedFrom               []string
}

// SelectPublishingProfile evaluates a publishing-profile claim (§7.4, ADR-034):
// registry routing never establishes trust, same-source promotion proves
// artifact equality only under a reproducible-build profile, and each
// ecosystem's default resolution must hide or defer a trust pre-release rather
// than serve it as an ordinary install.
//
// It returns whether the claim holds and, when it does not, a stable reason
// (empty on success). A faithful port of the conformance oracle's
// _publishing_profile_result; the production verifier feeds it real resolver /
// registry facts (tracked in semver-trust-go#76).
func SelectPublishingProfile(in PublishInputs) (accepted bool, reason string) {
	switch in.Claim {
	case "registry_routing_establishes_trust":
		if !in.AttestationVerified {
			return false, "registry_not_authority"
		}
		return true, ""

	case "same_source_promotion":
		if in.SourceRevision != in.PromotedSourceRevision {
			return false, "source_identity_mismatch"
		}
		return true, ""

	case "same_source_promotion_proves_artifact_equality":
		if in.SourceRevision != in.PromotedSourceRevision {
			return false, "source_identity_mismatch"
		}
		if !in.HasReproducibleBuildProfile {
			return false, "artifact_equality_unproven"
		}
		if in.ArtifactDigest != in.PromotedArtifactDigest {
			return false, "artifact_digest_mismatch"
		}
		return true, ""
	}

	switch {
	case in.Ecosystem == "go" && in.Claim == "default_query_hides_trust_prerelease":
		hasTrustPre := false
		for _, v := range in.RegistryVersions {
			if isTrustPrerelease(v) {
				hasTrustPre = true
				break
			}
		}
		if hasTrustPre && !hasReleaseVersion(in.RegistryVersions) {
			return false, "go_latest_prerelease_fallback"
		}
		return true, ""

	case in.Ecosystem == "npm" && in.Claim == "ordinary_install_avoids_trust_prerelease":
		if in.DistTagLatest != "" && isTrustPrerelease(in.DistTagLatest) && !in.OrdinaryInstallIntended {
			return false, "npm_latest_trust_prerelease"
		}
		return true, ""

	case in.Ecosystem == "cargo" && in.Claim == "default_dependency_avoids_trust_prerelease":
		return true, ""

	case in.Ecosystem == "pypi" && in.Claim == "publish_trust_prerelease_projection":
		projections := map[string]string{}
		for _, tag := range in.ProjectedFrom {
			projected, ok := pypiRCProjection(tag)
			if !ok {
				continue
			}
			if prior, seen := projections[projected]; seen {
				if prior != tag {
					return false, "non_injective_projection"
				}
			} else {
				projections[projected] = tag
			}
		}
		return false, "pypi_projection_deferred"
	}

	return false, "unsupported_profile_claim"
}

func isTrustPrerelease(version string) bool {
	return trustPrereleaseRe.MatchString(version)
}

// hasReleaseVersion reports whether any version is a plain release (a valid
// SemVer with no pre-release identifier).
func hasReleaseVersion(versions []string) bool {
	for _, v := range versions {
		if semverRe.MatchString(v) && !containsDash(v) {
			return true
		}
	}
	return false
}

func containsDash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			return true
		}
	}
	return false
}

// pypiRCProjection maps a trust tag to its PyPI rc projection ({core}rc{iter});
// ok is false for a clean (non-trust) tag or a non-tag, mirroring the oracle's
// None return.
func pypiRCProjection(tag string) (string, bool) {
	m := trustTagRe.FindStringSubmatch(tag)
	if m == nil || m[2] == "" { // group 2 is the level; empty => clean tag
		return "", false
	}
	core, iter := m[1], m[3]
	return core + "rc" + iter, true
}
