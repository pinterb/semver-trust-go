// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/semver-trust/semver-trust-go/internal/trust"
)

func loadSpecExample(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/spec-section-9.toml")
	if err != nil {
		t.Fatalf("reading spec §9 example: %v", err)
	}
	return data
}

// TestParseSpecExample pins every field of the §9 reference example.
func TestParseSpecExample(t *testing.T) {
	p, err := Parse(loadSpecExample(t))
	if err != nil {
		t.Fatalf("Parse(spec §9 example): %v", err)
	}

	want := &Policy{
		Version:   "0.1",
		Threshold: trust.T2,
		Strategy:  trust.StrategyDemote,
		Scopes: map[string]string{
			"services/auth/**":    "auth",
			"services/billing/**": "billing",
			"pkg/**":              "common",
			"docs/**":             "docs",
		},
		Weights: map[string]Weight{
			"auth":    WeightCritical,
			"common":  WeightCritical,
			"billing": WeightHigh,
			"docs":    WeightLow,
		},
		Meta: Meta{
			Paths:         []string{".semver-trust/**", ".github/workflows/**", "CODEOWNERS"},
			RequiredLevel: trust.T3,
		},
		Derivations: []Derivation{
			{
				Name:    "openapi-server",
				Inputs:  []string{"api/openapi.yaml", "tools/oapi-codegen.version"},
				Command: "make generate",
				Outputs: []string{"internal/gen/**"},
			},
			{
				Name:    "gofmt",
				Inputs:  []string{"**/*.go"},
				Command: "gofmt -l -w .",
				Outputs: []string{"**/*.go"},
			},
		},
		Identity: Identity{
			Human: HumanIdentity{
				AllowedSigners: ".semver-trust/allowed_signers",
				OIDCIssuers:    []string{"https://accounts.example.com"},
			},
			Agent: AgentIdentity{
				OIDCIssuers:     []string{"https://token.actions.githubusercontent.com"},
				SubjectPatterns: []string{"repo:acme/platform:*"},
				BotAccounts:     []string{"release-bot@acme.dev"},
			},
		},
		TrailersRequired: true,
		GraphAdapter:     AdapterGomod,
		Evidence: map[string]Evidence{
			"go": {Compat: "apidiff", CoverageMinChangedLines: 0.70},
		},
		Registry: map[string]Registry{
			"npm": {DistTagPrefix: "trust-"},
		},
	}

	if p.Digest == "" || len(p.Digest) != 64 {
		t.Errorf("Digest = %q, want 64 hex chars", p.Digest)
	}
	got := *p
	got.Digest = ""
	if !reflect.DeepEqual(&got, want) {
		t.Errorf("Parse(spec §9 example) mismatch:\ngot  %+v\nwant %+v", &got, want)
	}
}

// TestRoundTrip is the GO-023 acceptance: the §9 reference example
// round-trips — Parse ∘ Marshal ∘ Parse is identity on the loaded policy.
func TestRoundTrip(t *testing.T) {
	p1, err := Parse(loadSpecExample(t))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out, err := p1.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	p2, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse(Marshal(p)): %v\nmarshalled:\n%s", err, out)
	}

	p1.Digest, p2.Digest = "", ""
	if !reflect.DeepEqual(p1, p2) {
		t.Errorf("round-trip mismatch:\nfirst  %+v\nsecond %+v\nmarshalled:\n%s", p1, p2, out)
	}
}

// TestParseRejects covers the strictness contract: unknown keys and values
// outside the §9 vocabulary are errors, not warnings.
func TestParseRejects(t *testing.T) {
	valid := string(loadSpecExample(t))
	tests := []struct {
		name    string
		mutate  func(string) string
		wantSub string
	}{
		{
			name:    "unknown top-level table",
			mutate:  func(s string) string { return s + "\n[surprise]\nkey = 1\n" },
			wantSub: "unknown keys",
		},
		{
			name:    "unknown key in [policy]",
			mutate:  func(s string) string { return strings.Replace(s, "[policy]", "[policy]\ntreshold = \"T2\"", 1) },
			wantSub: "unknown keys",
		},
		{
			name:    "unknown key in [meta]",
			mutate:  func(s string) string { return strings.Replace(s, "[meta]", "[meta]\nrequried = true", 1) },
			wantSub: "unknown keys",
		},
		{
			name:    "unknown key in [identity.human]",
			mutate:  func(s string) string { return strings.Replace(s, "[identity.human]", "[identity.human]\nkeys = []", 1) },
			wantSub: "unknown keys",
		},
		{
			name:    "unknown key in [trailers]",
			mutate:  func(s string) string { return strings.Replace(s, "require = true", "require = true\nrequire_signed = true", 1) },
			wantSub: "unknown keys",
		},
		{
			name:    "unknown key in [graph]",
			mutate:  func(s string) string { return strings.Replace(s, "[graph]", "[graph]\nfallback = \"none\"", 1) },
			wantSub: "unknown keys",
		},
		{
			name:    "unknown key in [evidence.go]",
			mutate:  func(s string) string { return strings.Replace(s, "[evidence.go]", "[evidence.go]\nfuzzing = true", 1) },
			wantSub: "unknown keys",
		},
		{
			name:    "unknown key in [registry.npm]",
			mutate:  func(s string) string { return strings.Replace(s, "[registry.npm]", "[registry.npm]\naccess = \"public\"", 1) },
			wantSub: "unknown keys",
		},
		{
			name:    "unknown key in [[derivation]]",
			mutate:  func(s string) string { return strings.Replace(s, "command = \"make generate\"", "command = \"make generate\"\nshell = \"bash\"", 1) },
			wantSub: "unknown keys",
		},
		{
			name:    "missing [policy] table",
			mutate:  func(s string) string { return strings.Replace(s, "[policy]", "[trailers2]", 1) },
			wantSub: "unknown keys", // the orphaned keys under a renamed table trip strict mode first
		},
		{
			name:    "unsupported policy version",
			mutate:  func(s string) string { return strings.Replace(s, `version   = "0.1"`, `version   = "0.9"`, 1) },
			wantSub: "unsupported policy version",
		},
		{
			name:    "invalid threshold",
			mutate:  func(s string) string { return strings.Replace(s, `threshold = "T2"`, `threshold = "T9"`, 1) },
			wantSub: "invalid trust level",
		},
		{
			name:    "invalid strategy",
			mutate:  func(s string) string { return strings.Replace(s, `strategy  = "demote"`, `strategy  = "escalate"`, 1) },
			wantSub: "invalid strategy",
		},
		{
			name:    "invalid weight",
			mutate:  func(s string) string { return strings.Replace(s, `docs    = "low"`, `docs    = "tiny"`, 1) },
			wantSub: "invalid weight",
		},
		{
			name:    "weight for undeclared scope",
			mutate:  func(s string) string { return strings.Replace(s, `docs    = "low"`, `payments = "low"`, 1) },
			wantSub: "unknown scope",
		},
		{
			name:    "scope glob mapping to a table",
			mutate:  func(s string) string { return strings.Replace(s, "[scopes.weights]", "[scopes.oops]", 1) },
			wantSub: "must map to a non-empty scope name",
		},
		{
			name:    "invalid meta required_level",
			mutate:  func(s string) string { return strings.Replace(s, `required_level = "T3"`, `required_level = "max"`, 1) },
			wantSub: "invalid trust level",
		},
		{
			name: "missing meta paths",
			mutate: func(s string) string {
				return strings.Replace(s, `paths          = [".semver-trust/**", ".github/workflows/**", "CODEOWNERS"]`, `paths          = []`, 1)
			},
			wantSub: "§5.4",
		},
		{
			name:    "invalid graph adapter",
			mutate:  func(s string) string { return strings.Replace(s, `adapter = "gomod"`, `adapter = "maven"`, 1) },
			wantSub: "graph adapter",
		},
		{
			name:    "duplicate derivation name",
			mutate:  func(s string) string { return strings.Replace(s, `name    = "gofmt"`, `name    = "openapi-server"`, 1) },
			wantSub: "declared twice",
		},
		{
			name: "derivation without inputs",
			mutate: func(s string) string {
				return strings.Replace(s, `inputs  = ["api/openapi.yaml", "tools/oapi-codegen.version"]`, `inputs  = []`, 1)
			},
			wantSub: "inputs are required",
		},
		{
			name: "coverage out of range",
			mutate: func(s string) string {
				return strings.Replace(s, "coverage_min_changed_lines  = 0.70", "coverage_min_changed_lines  = 1.70", 1)
			},
			wantSub: "out of range",
		},
		{
			name:    "malformed TOML",
			mutate:  func(s string) string { return s + "\nthis is not toml\n" },
			wantSub: "policy:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := tt.mutate(valid)
			if mutated == valid {
				t.Fatal("mutation did not change the input; test is vacuous")
			}
			_, err := Parse([]byte(mutated))
			if err == nil {
				t.Fatalf("Parse accepted invalid policy (wanted error containing %q)", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantSub)
			}
		})
	}
}

// TestParseDefaults pins the degraded-gracefully defaults: absent [graph]
// means no workspace graph (AdapterNone), absent [trailers] means trailers
// are not policy-mandated.
func TestParseDefaults(t *testing.T) {
	minimal := `
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T3"
`
	p, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse(minimal): %v", err)
	}
	if p.GraphAdapter != AdapterNone {
		t.Errorf("GraphAdapter = %q, want %q", p.GraphAdapter, AdapterNone)
	}
	if p.TrailersRequired {
		t.Error("TrailersRequired = true, want false when [trailers] is absent")
	}
	if len(p.Scopes) != 0 || len(p.Weights) != 0 || len(p.Derivations) != 0 {
		t.Errorf("expected empty scopes/weights/derivations, got %+v", p)
	}
}

// TestDigestPinsBytes pins that the digest is a property of the exact bytes:
// any byte change — even a comment — produces a different digest (§10 step 1
// records the policy digest so the attestation pins what was actually read).
func TestDigestPinsBytes(t *testing.T) {
	data := loadSpecExample(t)
	p1, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	p2, err := Parse(append([]byte("# comment\n"), data...))
	if err != nil {
		t.Fatalf("Parse with comment: %v", err)
	}
	if p1.Digest == p2.Digest {
		t.Error("digest unchanged after byte change")
	}
}
