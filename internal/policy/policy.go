// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	"github.com/semver-trust/semver-trust-go/internal/trust"
)

// SchemaVersion is the policy schema version this loader implements (§9).
// A policy declaring any other version has unknown semantics and is rejected
// (config is the root of trust).
const SchemaVersion = "0.1"

// Weight is a scope's blast-radius criticality (§6.2, §9 [scopes.weights]).
type Weight uint8

const (
	WeightLow Weight = iota
	WeightModerate
	WeightHigh
	WeightCritical
)

// ParseWeight parses the §9 weight vocabulary.
func ParseWeight(s string) (Weight, error) {
	switch s {
	case "low":
		return WeightLow, nil
	case "moderate":
		return WeightModerate, nil
	case "high":
		return WeightHigh, nil
	case "critical":
		return WeightCritical, nil
	default:
		return 0, fmt.Errorf("invalid weight %q (want low|moderate|high|critical)", s)
	}
}

// String returns the §9 form of the weight.
func (w Weight) String() string {
	switch w {
	case WeightLow:
		return "low"
	case WeightModerate:
		return "moderate"
	case WeightHigh:
		return "high"
	case WeightCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// graphAdapters is the §9 [graph] adapter vocabulary. AdapterNone is the
// degraded-gracefully default when [graph] is absent: no workspace graph,
// no transitive propagation beyond own trust.
const (
	AdapterGomod = "gomod"
	AdapterPnpm  = "pnpm"
	AdapterCargo = "cargo"
	AdapterBazel = "bazel"
	AdapterNone  = "none"
)

// Policy is a loaded, validated policy file (§9).
type Policy struct {
	// Version is the policy schema version (always SchemaVersion once
	// validated).
	Version string

	// Threshold is the minimum effective trust for the clean channel.
	Threshold trust.Level

	// Strategy is the §6.3 enforcement strategy.
	Strategy trust.Strategy

	// Scopes maps path globs to scope names (§5.1). Paths matching no glob
	// fall into the implicit "default" scope.
	Scopes map[string]string

	// Weights maps scope names to blast-radius criticality (§6.2).
	Weights map[string]Weight

	// Meta declares the meta-paths whose commits must meet RequiredLevel
	// (§5.4).
	Meta Meta

	// Derivations are the §4.4 derivation rules, in declaration order.
	Derivations []Derivation

	// Identity is the §4.2/§9 identity map.
	Identity Identity

	// TrailersRequired reports whether commits on protected branches must
	// carry Provenance trailers (§4.1).
	TrailersRequired bool

	// GraphAdapter names the workspace graph adapter (§5.3); AdapterNone
	// when absent.
	GraphAdapter string

	// Evidence maps ecosystem names to evidence-provider configuration
	// (§6.1-§6.2).
	Evidence map[string]Evidence

	// Registry maps registry names to projection configuration (§7.4).
	Registry map[string]Registry

	// Digest is the lowercase-hex SHA-256 of the raw policy bytes, the value
	// pinned in release attestations (§8.1, §10 step 1).
	Digest string
}

// Meta is the §5.4 meta-path declaration.
type Meta struct {
	Paths         []string
	RequiredLevel trust.Level
}

// Derivation is a §4.4 derivation rule: outputs are deterministically
// produced from inputs by the pinned command.
type Derivation struct {
	Name    string
	Inputs  []string
	Command string
	Outputs []string
}

// Identity is the §9 identity map by class (§4.2).
type Identity struct {
	Human HumanIdentity
	Agent AgentIdentity
}

// HumanIdentity configures verification of human identities.
type HumanIdentity struct {
	// AllowedSigners is the path to an SSH allowed-signers registry.
	AllowedSigners string
	// OIDCIssuers are gitsign issuers whose identities map to people.
	OIDCIssuers []string
}

// AgentIdentity configures verification of machine identities.
type AgentIdentity struct {
	OIDCIssuers     []string
	SubjectPatterns []string
	BotAccounts     []string
}

// Evidence configures an ecosystem's evidence providers (§6.1-§6.2).
type Evidence struct {
	// Compat names the compatibility differ (e.g. "apidiff").
	Compat string
	// CoverageMinChangedLines is the minimum test coverage on changed lines,
	// in [0,1]; 0 means unset.
	CoverageMinChangedLines float64
}

// Registry configures a registry projection (§7.4).
type Registry struct {
	// DistTagPrefix is the npm dist-tag prefix (e.g. "trust-").
	DistTagPrefix string
}
