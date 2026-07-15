// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/semver-trust/semver-trust-go/internal/policy"
	"github.com/semver-trust/semver-trust-go/internal/vcs"
)

// Trust-material role names (§5.4/ADR-028): the transition binds a role to each
// declared trust-material registry. A bootstrap descriptor MUST name its roles
// with these same identifiers, so the role→path map it pins matches the one
// derived from the policy here (SelectPolicyTransition compares them by value).
const (
	// RoleHumanSigners names the identity.human.allowed_signers registry.
	RoleHumanSigners = "human_signers"
	// RoleHumanGPG names the identity.human.gpg_keyring registry.
	RoleHumanGPG = "human_gpg"
	// RoleAttesters names the identity.attestation_signers registry.
	RoleAttesters = "attesters"
)

// MetaPolicyFromTree builds the §5.4/ADR-028 transition-facing view of a policy
// (policy.MetaPolicy) from an already-parsed policy and TO's tree. Trust material
// is digest-pinned: each declared identity registry (allowed-signers, GPG
// keyring, attestation-signers) is read from the tree and hashed, so a bootstrap
// descriptor can authenticate the exact bytes; AuthorizedSigners are the
// principals of the tree's allowed-signers registry. The policy's own digest is
// re-expressed in the sha256:<hex> form the descriptor and the transition
// compare against (Policy.Digest itself is bare hex).
//
// It is the production producer that feeds policy.SelectPolicyTransition, and the
// reference a descriptor author uses to compute matching policy facts.
func MetaPolicyFromTree(pol *policy.Policy, policyPath, repoPath, rev string) (policy.MetaPolicy, error) {
	mp := policy.MetaPolicy{
		Path:          policyPath,
		Digest:        "sha256:" + pol.Digest,
		RequiredLevel: pol.Meta.RequiredLevel.String(),
		MetaPaths:     pol.Meta.Paths,
	}
	if pol.AdoptionBoundary != "" {
		b := pol.AdoptionBoundary
		mp.AdoptionBoundary = &b
	}

	registries := []struct{ role, path string }{
		{RoleHumanSigners, pol.Identity.Human.AllowedSigners},
		{RoleHumanGPG, pol.Identity.Human.GPGKeyring},
		{RoleAttesters, pol.Identity.AttestationSigners},
	}
	trustMaterial := map[string]string{}
	trustRoles := map[string]string{}
	for _, reg := range registries {
		if reg.path == "" {
			continue
		}
		digest, err := treeFileDigest(repoPath, rev, reg.path)
		if err != nil {
			return policy.MetaPolicy{}, fmt.Errorf("meta-policy: trust material %q: %w", reg.path, err)
		}
		trustMaterial[reg.path] = digest
		trustRoles[reg.role] = reg.path
	}
	mp.TrustMaterial = trustMaterial
	mp.TrustRoles = trustRoles

	// AuthorizedSigners are the commit-signer principals of every trust family
	// the verifier accepts — SSH allowed-signers AND the OpenPGP keyring — each
	// matching the principal VerifyCommitSignature returns, so the transition's
	// unknown_active_signer gate never rejects a valid commit. A GPG-only policy
	// must still populate its signers (go#96 review).
	seen := map[string]bool{}
	add := func(principal string) {
		if !seen[principal] {
			seen[principal] = true
			mp.AuthorizedSigners = append(mp.AuthorizedSigners, principal)
		}
	}
	if p := pol.Identity.Human.AllowedSigners; p != "" {
		data, err := readTreeFile(repoPath, rev, p)
		if err != nil {
			return policy.MetaPolicy{}, fmt.Errorf("meta-policy: allowed-signers %q: %w", p, err)
		}
		allowed, err := vcs.ParseAllowedSigners(data)
		if err != nil {
			return policy.MetaPolicy{}, fmt.Errorf("meta-policy: allowed-signers %q: %w", p, err)
		}
		for _, s := range allowed {
			for _, principal := range s.Principals {
				add(principal)
			}
		}
	}
	if p := pol.Identity.Human.GPGKeyring; p != "" {
		data, err := readTreeFile(repoPath, rev, p)
		if err != nil {
			return policy.MetaPolicy{}, fmt.Errorf("meta-policy: gpg keyring %q: %w", p, err)
		}
		keyring, err := vcs.ParsePGPKeyring(data)
		if err != nil {
			return policy.MetaPolicy{}, fmt.Errorf("meta-policy: gpg keyring %q: %w", p, err)
		}
		for _, principal := range keyring.Principals() {
			add(principal)
		}
	}
	return mp, nil
}

// treeFileDigest returns the sha256:<hex> digest of a file in a revision's tree.
func treeFileDigest(repoPath, rev, path string) (string, error) {
	data, err := readTreeFile(repoPath, rev, path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
