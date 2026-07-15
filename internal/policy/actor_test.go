// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"reflect"
	"strings"
	"testing"
)

// actorPolicy is a minimal §9 policy declaring two canonical actors: alice
// (human, two credentials — a key rotation — plus an account) and review-bot
// (agent).
const actorPolicy = `
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"

[identity.actor.alice]
class       = "human"
credentials = ["ssh:SHA256:alice-old", "ssh:SHA256:alice-current"]
accounts    = ["github:alice"]

[identity.actor.review-bot]
class       = "agent"
credentials = ["oidc:repo:acme/platform:environment:review"]
accounts    = ["github:acme-review-bot"]
`

func TestParseActorMap(t *testing.T) {
	p, err := Parse([]byte(actorPolicy))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Identity.Actors) != 2 {
		t.Fatalf("actors = %v, want alice + review-bot", p.Identity.Actors)
	}
	alice := p.Identity.Actors["alice"]
	if alice.Class != "human" || len(alice.Credentials) != 2 || len(alice.Accounts) != 1 {
		t.Errorf("alice = %+v", alice)
	}

	cases := []struct {
		identity     string
		wantActor    string
		wantClass    string
		wantResolved bool
	}{
		{"ssh:SHA256:alice-old", "alice", "human", true},
		{"ssh:SHA256:alice-current", "alice", "human", true}, // rotation → same actor
		{"github:alice", "alice", "human", true},             // account resolves too
		{"oidc:repo:acme/platform:environment:review", "review-bot", "agent", true},
		{"github:acme-review-bot", "review-bot", "agent", true},
		{"ssh:SHA256:unknown", "", "", false},
	}
	for _, c := range cases {
		id, class, ok := p.ResolveActor(c.identity)
		if id != c.wantActor || class != c.wantClass || ok != c.wantResolved {
			t.Errorf("ResolveActor(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.identity, id, class, ok, c.wantActor, c.wantClass, c.wantResolved)
		}
	}
}

// TestActorMapRoundTrip pins the marshal contract for the new vocabulary:
// Parse(Marshal(p)) must round-trip the canonical-actor map, or a normalize/
// edit/emit pass through Marshal would silently drop it and disable qualified
// review. Map iteration order is nondeterministic, so compare parsed policies
// rather than raw TOML bytes (like TestRoundTrip).
func TestActorMapRoundTrip(t *testing.T) {
	p1, err := Parse([]byte(actorPolicy))
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
	if len(p2.Identity.Actors) != 2 {
		t.Fatalf("Actors after round-trip = %v, want alice + review-bot\nmarshalled:\n%s", p2.Identity.Actors, out)
	}
	p1.Digest, p2.Digest = "", ""
	if !reflect.DeepEqual(p1.Identity.Actors, p2.Identity.Actors) {
		t.Errorf("actor-map round-trip mismatch:\nfirst  %+v\nsecond %+v\nmarshalled:\n%s",
			p1.Identity.Actors, p2.Identity.Actors, out)
	}
}

func TestParseActorMapRejects(t *testing.T) {
	base := actorPolicy
	cases := []struct {
		name    string
		policy  string
		wantSub string
	}{
		{
			name: "duplicate credential across actors",
			policy: base + `
[identity.actor.mallory]
class       = "human"
credentials = ["ssh:SHA256:alice-current"]
`,
			wantSub: "maps to both",
		},
		{
			name: "duplicate account across actors",
			policy: base + `
[identity.actor.mallory]
class    = "human"
accounts = ["github:alice"]
`,
			wantSub: "maps to both",
		},
		{
			name: "unknown class",
			policy: `
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"
[meta]
paths          = [".semver-trust/**"]
required_level = "T2"
[identity.actor.robo]
class       = "robot"
credentials = ["ssh:SHA256:x"]
`,
			wantSub: `must be "human" or "agent"`,
		},
		{
			name: "empty actor",
			policy: `
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"
[meta]
paths          = [".semver-trust/**"]
required_level = "T2"
[identity.actor.ghost]
class = "human"
`,
			wantSub: "at least one credential or account",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.policy))
			if err == nil {
				t.Fatalf("expected a parse error for %s", c.name)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("error = %v, want substring %q", err, c.wantSub)
			}
		})
	}
}

// TestNoActorMap: a policy with no [identity.actor.*] leaves Identity.Actors nil
// (the qualified-review path is not gated on), and ResolveActor never resolves.
func TestNoActorMap(t *testing.T) {
	p, err := Parse([]byte(`
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"
[meta]
paths          = [".semver-trust/**"]
required_level = "T2"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Identity.Actors != nil {
		t.Errorf("Actors = %v, want nil for a policy declaring no actors", p.Identity.Actors)
	}
	if _, _, ok := p.ResolveActor("ssh:SHA256:anything"); ok {
		t.Error("ResolveActor resolved against an empty actor map")
	}
}
