// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/semver-trust/semver-trust-go/internal/trust"
)

// The raw shapes mirror the §9 TOML layout exactly. Decoding runs with
// DisallowUnknownFields, so any key that does not map to a field below is an
// error — with two deliberate map-typed exceptions whose keys are data, not
// schema: [scopes] (glob keys, hand-validated in validateScopes) and the
// ecosystem/registry names under [evidence] and [registry] (whose *values*
// are strict structs).
type rawPolicy struct {
	Policy     *rawHeader             `toml:"policy"`
	Scopes     map[string]any         `toml:"scopes"`
	Meta       *rawMeta               `toml:"meta"`
	Derivation []rawDerivation        `toml:"derivation"`
	Identity   rawIdentity            `toml:"identity"`
	Trailers   rawTrailers            `toml:"trailers"`
	Graph      rawGraph               `toml:"graph"`
	Evidence   map[string]rawEvidence `toml:"evidence"`
	Registry   map[string]rawRegistry `toml:"registry"`
}

type rawHeader struct {
	Version   string `toml:"version"`
	Threshold string `toml:"threshold"`
	Strategy  string `toml:"strategy"`
}

type rawMeta struct {
	Paths         []string `toml:"paths"`
	RequiredLevel string   `toml:"required_level"`
}

type rawDerivation struct {
	Name    string   `toml:"name"`
	Inputs  []string `toml:"inputs"`
	Command string   `toml:"command"`
	Outputs []string `toml:"outputs"`
}

type rawIdentity struct {
	Human rawHumanIdentity `toml:"human"`
	Agent rawAgentIdentity `toml:"agent"`
}

type rawHumanIdentity struct {
	AllowedSigners string   `toml:"allowed_signers"`
	OIDCIssuers    []string `toml:"oidc_issuers"`
}

type rawAgentIdentity struct {
	OIDCIssuers     []string `toml:"oidc_issuers"`
	SubjectPatterns []string `toml:"subject_patterns"`
	BotAccounts     []string `toml:"bot_accounts"`
}

type rawTrailers struct {
	Require bool `toml:"require"`
}

type rawGraph struct {
	Adapter string `toml:"adapter"`
}

type rawEvidence struct {
	Compat                  string  `toml:"compat"`
	CoverageMinChangedLines float64 `toml:"coverage_min_changed_lines"`
}

type rawRegistry struct {
	DistTagPrefix string `toml:"dist_tag_prefix"`
}

// Parse loads and validates a policy file from its raw bytes. Unknown keys,
// values outside the §9 vocabulary, and structurally incomplete policies are
// all errors (§5.4: the config protects the system; the system must protect
// the config).
func Parse(data []byte) (*Policy, error) {
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var raw rawPolicy
	if err := dec.Decode(&raw); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			return nil, fmt.Errorf("policy: unknown keys (config is the root of trust; unknown keys are errors):\n%s", strict.String())
		}
		return nil, fmt.Errorf("policy: %w", err)
	}

	p := &Policy{
		Scopes:   map[string]string{},
		Weights:  map[string]Weight{},
		Evidence: map[string]Evidence{},
		Registry: map[string]Registry{},
	}

	if err := parseHeader(raw.Policy, p); err != nil {
		return nil, err
	}
	if err := parseScopes(raw.Scopes, p); err != nil {
		return nil, err
	}
	if err := parseMeta(raw.Meta, p); err != nil {
		return nil, err
	}
	if err := parseDerivations(raw.Derivation, p); err != nil {
		return nil, err
	}
	if err := parseGraph(raw.Graph, p); err != nil {
		return nil, err
	}
	if err := parseEvidence(raw.Evidence, p); err != nil {
		return nil, err
	}

	p.Identity = Identity{
		Human: HumanIdentity(raw.Identity.Human),
		Agent: AgentIdentity(raw.Identity.Agent),
	}
	p.TrailersRequired = raw.Trailers.Require
	for name, r := range raw.Registry {
		p.Registry[name] = Registry(r)
	}

	sum := sha256.Sum256(data)
	p.Digest = hex.EncodeToString(sum[:])
	return p, nil
}

func parseHeader(h *rawHeader, p *Policy) error {
	if h == nil {
		return fmt.Errorf("policy: missing required [policy] table")
	}
	if h.Version != SchemaVersion {
		return fmt.Errorf("policy: unsupported policy version %q (this loader implements %q)", h.Version, SchemaVersion)
	}
	p.Version = h.Version

	threshold, err := trust.ParseLevel(h.Threshold)
	if err != nil {
		return fmt.Errorf("policy: threshold: %w", err)
	}
	p.Threshold = threshold

	strategy, err := ParseStrategy(h.Strategy)
	if err != nil {
		return fmt.Errorf("policy: strategy: %w", err)
	}
	p.Strategy = strategy
	return nil
}

// parseScopes validates the [scopes] table by hand: its keys are path globs
// (data, not schema), except the reserved "weights" key holding the
// scope-name → criticality table. Anything else in there is an unknown key.
func parseScopes(scopes map[string]any, p *Policy) error {
	weights := map[string]any{}
	for key, value := range scopes {
		if key == "weights" {
			w, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("policy: [scopes.weights] must be a table of scope name -> weight")
			}
			weights = w
			continue
		}
		name, ok := value.(string)
		if !ok || name == "" {
			return fmt.Errorf("policy: scope glob %q must map to a non-empty scope name (\"weights\" is the only table allowed under [scopes])", key)
		}
		p.Scopes[key] = name
	}

	declared := map[string]bool{"default": true}
	for _, name := range p.Scopes {
		declared[name] = true
	}
	for scope, value := range weights {
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("policy: weight for scope %q must be a string", scope)
		}
		w, err := ParseWeight(s)
		if err != nil {
			return fmt.Errorf("policy: weight for scope %q: %w", scope, err)
		}
		if !declared[scope] {
			return fmt.Errorf("policy: weight declared for unknown scope %q (not a [scopes] name or \"default\")", scope)
		}
		p.Weights[scope] = w
	}
	return nil
}

// parseMeta requires the [meta] table: §5.4 says the policy file, scope map,
// derivation rules, identity map, and attestation workflows MUST be declared
// as meta-paths, so a policy that declares none cannot be §5.4-compliant.
func parseMeta(m *rawMeta, p *Policy) error {
	if m == nil || len(m.Paths) == 0 {
		return fmt.Errorf("policy: [meta] must declare at least the policy file's own path (§5.4)")
	}
	for _, path := range m.Paths {
		if path == "" {
			return fmt.Errorf("policy: [meta] paths must be non-empty globs")
		}
	}
	level, err := trust.ParseLevel(m.RequiredLevel)
	if err != nil {
		return fmt.Errorf("policy: meta required_level: %w", err)
	}
	p.Meta = Meta{Paths: m.Paths, RequiredLevel: level}
	return nil
}

func parseDerivations(rules []rawDerivation, p *Policy) error {
	seen := map[string]bool{}
	for i, r := range rules {
		switch {
		case r.Name == "":
			return fmt.Errorf("policy: derivation %d: name is required", i)
		case seen[r.Name]:
			return fmt.Errorf("policy: derivation %q declared twice", r.Name)
		case len(r.Inputs) == 0:
			return fmt.Errorf("policy: derivation %q: inputs are required (the toolchain pin lives there, §4.4)", r.Name)
		case r.Command == "":
			return fmt.Errorf("policy: derivation %q: command is required", r.Name)
		case len(r.Outputs) == 0:
			return fmt.Errorf("policy: derivation %q: outputs are required", r.Name)
		}
		seen[r.Name] = true
		p.Derivations = append(p.Derivations, Derivation(r))
	}
	return nil
}

func parseGraph(g rawGraph, p *Policy) error {
	switch g.Adapter {
	case "":
		p.GraphAdapter = AdapterNone
	case AdapterGomod, AdapterPnpm, AdapterCargo, AdapterBazel, AdapterNone:
		p.GraphAdapter = g.Adapter
	default:
		return fmt.Errorf("policy: graph adapter %q (want gomod|pnpm|cargo|bazel|none)", g.Adapter)
	}
	return nil
}

func parseEvidence(evidence map[string]rawEvidence, p *Policy) error {
	for eco, e := range evidence {
		if e.CoverageMinChangedLines < 0 || e.CoverageMinChangedLines > 1 {
			return fmt.Errorf("policy: evidence.%s coverage_min_changed_lines %v out of range [0,1]", eco, e.CoverageMinChangedLines)
		}
		p.Evidence[eco] = Evidence(e)
	}
	return nil
}
