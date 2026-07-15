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
	// AdoptionBoundary is a pointer so a declared-but-empty boundary is
	// distinguishable from an absent one: `adoption_boundary = ""` is a
	// rejected declaration, not a no-op (ADR-026).
	AdoptionBoundary *string `toml:"adoption_boundary,omitempty"`
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
	// Actor is the §9 canonical-actor map, keyed by actor id (a data key, the
	// [evidence.<eco>] pattern). Absent means the policy declares no actors.
	Actor map[string]rawActor `toml:"actor"`
	// AttestationSigners is a pointer for the same reason as AdoptionBoundary:
	// `attestation_signers = ""` is a rejected declaration, not an absent one
	// (§9, ADR-022). It sits under [identity], not [identity.human] — review
	// and release attestations may be signed by any accountable class.
	AttestationSigners *string `toml:"attestation_signers,omitempty"`
}

type rawHumanIdentity struct {
	AllowedSigners string   `toml:"allowed_signers"`
	OIDCIssuers    []string `toml:"oidc_issuers"`
	// GPGKeyring is a pointer so a declared-but-empty keyring path is
	// distinguishable from an absent one and rejected (§9, the OpenPGP
	// counterpart to the SSH allowed_signers registry).
	GPGKeyring *string `toml:"gpg_keyring,omitempty"`
}

type rawAgentIdentity struct {
	OIDCIssuers     []string `toml:"oidc_issuers"`
	SubjectPatterns []string `toml:"subject_patterns"`
	BotAccounts     []string `toml:"bot_accounts"`
}
type rawActor struct {
	Class       string   `toml:"class"`
	Credentials []string `toml:"credentials"`
	Accounts    []string `toml:"accounts"`
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

	if err := parseIdentity(raw.Identity, p); err != nil {
		return nil, err
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

	strategy, err := trust.ParseStrategy(h.Strategy)
	if err != nil {
		return fmt.Errorf("policy: strategy: %w", err)
	}
	p.Strategy = strategy

	if h.AdoptionBoundary != nil {
		if *h.AdoptionBoundary == "" {
			return fmt.Errorf("policy: adoption_boundary must be a non-empty revision when declared (ADR-026)")
		}
		p.AdoptionBoundary = *h.AdoptionBoundary
	}
	return nil
}

// parseIdentity copies the §9 identity map onto the policy, validating the two
// optional trust-material paths. Both follow the adoption_boundary rule: a
// declared-but-empty path is a rejected declaration, not a no-op — an empty
// gpg_keyring or attestation_signers is a typo in the root of trust, never a
// silent "no keyring".
func parseIdentity(raw rawIdentity, p *Policy) error {
	human := HumanIdentity{
		AllowedSigners: raw.Human.AllowedSigners,
		OIDCIssuers:    raw.Human.OIDCIssuers,
	}
	if raw.Human.GPGKeyring != nil {
		if *raw.Human.GPGKeyring == "" {
			return fmt.Errorf("policy: identity.human gpg_keyring must be a non-empty path when declared (§9)")
		}
		human.GPGKeyring = *raw.Human.GPGKeyring
	}

	id := Identity{Human: human, Agent: AgentIdentity(raw.Agent)}
	if raw.AttestationSigners != nil {
		if *raw.AttestationSigners == "" {
			return fmt.Errorf("policy: identity attestation_signers must be a non-empty path when declared (§9, ADR-022)")
		}
		id.AttestationSigners = *raw.AttestationSigners
	}

	actors, err := parseActors(raw.Actor)
	if err != nil {
		return err
	}
	id.Actors = actors

	p.Identity = id
	return nil
}

// parseActors validates the §4.2/§9 canonical-actor map: each actor has a
// human/agent class and at least one credential or account, and — the
// load-bearing §9 invariant — no credential or platform account appears under
// more than one actor (else the verifier could not tell which actor a credential
// counts as).
func parseActors(raw map[string]rawActor) (map[string]Actor, error) {
	if len(raw) == 0 {
		return nil, nil // no actor map declared — leave Identity.Actors nil
	}
	actors := make(map[string]Actor, len(raw))
	seenCred := map[string]string{}
	seenAcct := map[string]string{}
	for actorID, a := range raw {
		if actorID == "" {
			return nil, fmt.Errorf("policy: identity.actor id must be non-empty")
		}
		if a.Class != "human" && a.Class != "agent" {
			return nil, fmt.Errorf("policy: identity.actor.%s class %q must be \"human\" or \"agent\" (§4.2)", actorID, a.Class)
		}
		if len(a.Credentials) == 0 && len(a.Accounts) == 0 {
			return nil, fmt.Errorf("policy: identity.actor.%s must declare at least one credential or account (§9)", actorID)
		}
		for _, c := range a.Credentials {
			if prior, ok := seenCred[c]; ok {
				return nil, fmt.Errorf("policy: credential %q maps to both identity.actor.%s and identity.actor.%s (a credential maps to exactly one actor, §9)", c, prior, actorID)
			}
			seenCred[c] = actorID
		}
		for _, acct := range a.Accounts {
			if prior, ok := seenAcct[acct]; ok {
				return nil, fmt.Errorf("policy: account %q maps to both identity.actor.%s and identity.actor.%s (an account maps to exactly one actor, §9)", acct, prior, actorID)
			}
			seenAcct[acct] = actorID
		}
		actors[actorID] = Actor(a)
	}
	return actors, nil
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
