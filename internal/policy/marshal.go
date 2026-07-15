// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	toml "github.com/pelletier/go-toml/v2"
)

// Marshal renders the policy back to §9 TOML. Comments are not preserved and
// key order follows the §9 table layout; the guarantee is semantic, not
// byte-level: Parse(Marshal(p)) equals p (modulo Digest, which is a property
// of the exact bytes).
func (p *Policy) Marshal() ([]byte, error) {
	scopes := map[string]any{}
	for glob, name := range p.Scopes {
		scopes[glob] = name
	}
	if len(p.Weights) > 0 {
		weights := map[string]any{}
		for scope, w := range p.Weights {
			weights[scope] = w.String()
		}
		scopes["weights"] = weights
	}

	header := &rawHeader{
		Version:   p.Version,
		Threshold: p.Threshold.String(),
		Strategy:  p.Strategy.String(),
	}
	if p.AdoptionBoundary != "" {
		header.AdoptionBoundary = &p.AdoptionBoundary
	}

	human := rawHumanIdentity{
		AllowedSigners: p.Identity.Human.AllowedSigners,
		OIDCIssuers:    p.Identity.Human.OIDCIssuers,
	}
	if p.Identity.Human.GPGKeyring != "" {
		human.GPGKeyring = &p.Identity.Human.GPGKeyring
	}
	identity := rawIdentity{
		Human: human,
		Agent: rawAgentIdentity(p.Identity.Agent),
	}
	if p.Identity.AttestationSigners != "" {
		identity.AttestationSigners = &p.Identity.AttestationSigners
	}
	// The canonical-actor map is the root-of-trust vocabulary for qualified
	// review (ADR-031); it must survive Parse(Marshal(p)) like every other
	// field. Emit it only when declared so a policy with no actors marshals
	// back to nil Actors (rawActor mirrors Actor field-for-field).
	if len(p.Identity.Actors) > 0 {
		actors := make(map[string]rawActor, len(p.Identity.Actors))
		for id, a := range p.Identity.Actors {
			actors[id] = rawActor(a)
		}
		identity.Actor = actors
	}

	raw := rawPolicy{
		Policy: header,
		Scopes: scopes,
		Meta: &rawMeta{
			Paths:         p.Meta.Paths,
			RequiredLevel: p.Meta.RequiredLevel.String(),
		},
		Identity: identity,
		Trailers: rawTrailers{Require: p.TrailersRequired},
		Graph:    rawGraph{Adapter: p.GraphAdapter},
		Evidence: map[string]rawEvidence{},
		Registry: map[string]rawRegistry{},
	}
	for _, d := range p.Derivations {
		raw.Derivation = append(raw.Derivation, rawDerivation(d))
	}
	for eco, e := range p.Evidence {
		raw.Evidence[eco] = rawEvidence(e)
	}
	for name, r := range p.Registry {
		raw.Registry[name] = rawRegistry(r)
	}

	out, err := toml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal: %w", err)
	}
	return out, nil
}
