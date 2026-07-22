// SPDX-License-Identifier: Apache-2.0

// Package setup plans and applies THIS clone's repo-local git configuration for the
// bootstrap family. It writes only enumerated .git/config keys through the git binary
// (ADR-042, via internal/gitconfig) — never --global, never the working tree, never a
// hook, never remote.<name>.push. The planner is pure over an injected Env (the
// command boundary does the I/O, crypto, and ambient reads), so every rule — the
// all-or-nothing conflict discipline (ADR-039), the never-force user.signingkey rule
// (SU-11), refspec idempotency (SU-9), the ADR-022 two-key cross-check, and the
// euid/GIT_DIR/bare refusals — is unit-testable without a filesystem.
package setup

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-git/go-git/v5/config"

	"github.com/semver-trust/semver-trust-go/internal/gitconfig"
	"github.com/semver-trust/semver-trust-go/internal/policy"
)

// Managed keys — the complete, closed set setup ever writes.
const (
	keyGPGFormat      = "gpg.format"
	keySigningKey     = "user.signingkey"
	keyCommitGPGSign  = "commit.gpgsign"
	keyCommitTemplate = "commit.template"
	keyAllowedSigners = "gpg.ssh.allowedSignersFile"

	// AttestationRefspec is the non-force fetch refspec that moves attestation
	// evidence (ADR-043); content-addressed refs never need force.
	AttestationRefspec = "refs/attestations/*:refs/attestations/*"
)

// ManagedKeys is the closed set of config keys setup reads (for the local-scope
// current values) and may write — the complete surface of what setup touches.
var ManagedKeys = []string{keyGPGFormat, keySigningKey, keyCommitGPGSign, keyCommitTemplate, keyAllowedSigners}

// ReadCurrents reads the repo-LOCAL value of every managed key — the Env.Current map
// Compute needs, so a value inherited from global or an include never leaks into
// conflict detection. A real read failure surfaces (fail closed).
func ReadCurrents(git gitconfig.Git) (map[string]string, error) {
	cur := map[string]string{}
	for _, k := range ManagedKeys {
		v, err := git.GetLocal(k)
		if err != nil {
			return nil, err
		}
		cur[k] = v
	}
	return cur, nil
}

// Action is what setup will do with one key.
type Action string

const (
	ActionSet    Action = "set"              // currently unset → write it
	ActionOK     Action = "ok (already set)" // current == desired → skip
	ActionForced Action = "forced"           // conflict, overwritten under --force
	ActionManual Action = "manual"           // include present → emit the command, don't write (SU-5)
)

// Change is one planned key mutation.
type Change struct {
	Key     string
	Current string
	Desired string
	Action  Action
}

// FetchChange is the attestation fetch-refspec append.
type FetchChange struct {
	Remote  string
	Refspec string
	Already bool // an equivalent refspec is already configured (idempotent)
}

// Plan is a validated, ready-to-apply (or dry-run) setup.
type Plan struct {
	Changes  []Change
	Fetch    *FetchChange
	Warnings []string
}

// Env is the injected context a Plan is computed from. The command boundary fills it
// (gitconfig.Load, the policy, .gitmessage/registry existence, the offered key's
// fingerprint, os.Geteuid, GIT_DIR/GIT_CONFIG*), so the planner performs no I/O.
type Env struct {
	Config *gitconfig.Config // merged config + environment facts (bare, includes, git path)
	Policy *policy.Policy     // parsed working-tree policy (may be nil)

	// Current holds the repo-LOCAL current value of each managed key (git config
	// --local --get; "" if absent). setup writes repo-local config, so conflicts are
	// computed against the LOCAL scope — a value inherited from global or an include
	// is overridden by a local write, not a conflict (that is exactly the point of a
	// per-repo signing key). The command fills this via gitconfig.Git.GetLocal.
	Current map[string]string

	// Signing mode — exactly one is non-empty.
	SigningKey    string // --signing-key: an SSH .pub path, stored as user.signingkey
	GPGSigningKey string // --gpg-signing-key: a GPG key id

	Remote              string   // --remote (default origin)
	RemoteURL           string   // current remote.<remote>.url (echo)
	RemoteFetchRefspecs []string // current remote.<remote>.fetch (idempotency)

	// Command-resolved facts that keep the planner pure.
	GitmessageExists     bool   // .gitmessage present → manage commit.template
	AllowedSignersPath   string // policy allowed_signers path (or default)
	AllowedSignersExists bool   // the file exists → manage gpg.ssh.allowedSignersFile (SSH mode)

	// ADR-022 two-key cross-check (SSH mode).
	SigningKeyFingerprint      string   // ssh.FingerprintSHA256 of --signing-key; "" otherwise
	AttestationSignersDeclared bool     // policy declares attestation_signers
	AttestationFingerprints    []string // fingerprints enrolled in attestation_signers
	AttestationReadErr         error    // declared-but-unreadable → fail closed

	Force        bool
	Euid         int
	GitDirEnv    bool // GIT_DIR set in the environment
	GitConfigEnv bool // GIT_CONFIG / GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM / GIT_CONFIG_COUNT set
}

type keyval struct{ key, desired, current string }

// Compute builds the full change-set and every refusal. A refusal returns a nil Plan
// and an error listing the reason(s); nothing is written (all-or-nothing, ADR-039).
func Compute(env Env) (*Plan, error) {
	if env.Config == nil {
		return nil, errors.New("setup: no git configuration loaded")
	}
	// Environment refusals (fail closed, write nothing).
	if env.Euid == 0 {
		return nil, errors.New("setup: refusing to run as root (euid 0) — run as your own user so config and any files stay yours (CC-4)")
	}
	if env.GitDirEnv || env.GitConfigEnv {
		return nil, errors.New("setup: refusing to write — GIT_DIR/GIT_CONFIG* is set in the environment, which redirects git config to an ambiguous target; unset it and re-run (SU-7)")
	}
	if env.Config.Bare {
		return nil, errors.New("setup: refusing to write — this is a bare repository (no working tree to configure commit signing for)")
	}
	if (env.SigningKey == "") == (env.GPGSigningKey == "") {
		return nil, errors.New("setup: exactly one of --signing-key or --gpg-signing-key is required")
	}

	// ADR-022/040: the offered SSH signing key must not also be an attestation key.
	// Fail CLOSED whenever the check cannot be run — an unreadable registry OR a
	// signing key that could not be fingerprinted at the boundary — so a loading
	// failure never silently bypasses the two-key invariant.
	if env.SigningKey != "" && env.AttestationSignersDeclared {
		if env.AttestationReadErr != nil {
			return nil, fmt.Errorf("setup: cannot verify two-key distinctness — attestation_signers unreadable: %w", env.AttestationReadErr)
		}
		if env.SigningKeyFingerprint == "" {
			return nil, errors.New("setup: cannot verify two-key distinctness — the offered signing key could not be fingerprinted; check the --signing-key .pub")
		}
		for _, fp := range env.AttestationFingerprints {
			if fp == env.SigningKeyFingerprint {
				return nil, errors.New("setup: this key is enrolled as an attestation key; commit and attestation keys must be distinct (ADR-022/040)")
			}
		}
	}

	p := &Plan{}
	if env.Config.HasIncludes {
		p.Warnings = append(p.Warnings, "include/includeIf present: a managed key may be governed by an included config; keys that are unset are shown as manual `git config` commands rather than written over a corporate include (SU-5)")
	}

	// Classify each managed key; collect conflicts for the all-or-nothing decision.
	var signingKeyConflict *Change
	var otherConflicts []Change
	for _, kv := range desiredKeys(env) {
		ch := Change{Key: kv.key, Current: kv.current, Desired: kv.desired}
		switch kv.current {
		case kv.desired:
			ch.Action = ActionOK
		case "":
			// Genuinely unset (locally). Under an include environment, don't
			// auto-write — emit the manual command instead (SU-5).
			if env.Config.HasIncludes {
				ch.Action = ActionManual
			} else {
				ch.Action = ActionSet
			}
		default:
			// Conflict: currently set (locally) to a different value.
			if kv.key == keySigningKey {
				// SU-11: the signing identity is NEVER overwritten by a flag — swapping
				// a company-mandated key silently is the one overwrite no --force performs.
				c := ch
				signingKeyConflict = &c
				continue
			}
			if env.Force {
				ch.Action = ActionForced
			} else {
				otherConflicts = append(otherConflicts, ch)
				continue
			}
		}
		p.Changes = append(p.Changes, ch)
	}

	// All-or-nothing (ADR-039): any conflict refuses the whole run and the precomputed
	// refusal lists EVERY conflict, writing nothing — the human fixes them all in one
	// pass, never discovering a second conflict on a re-run. The signing-key line is
	// force-immune and never suggests --force; the --force hint (if shown) is scoped to
	// the non-identity conflicts.
	if signingKeyConflict != nil || len(otherConflicts) > 0 {
		var b strings.Builder
		b.WriteString("setup: refusing to overwrite already-set config (write nothing):")
		if signingKeyConflict != nil {
			fmt.Fprintf(&b, "\n  %s is %q, want %q — the signing identity is never overwritten by a flag; change it by hand if you mean to: git config %s %q",
				keySigningKey, signingKeyConflict.Current, signingKeyConflict.Desired, keySigningKey, signingKeyConflict.Desired)
		}
		for _, c := range otherConflicts {
			fmt.Fprintf(&b, "\n  %s is %q, want %q", c.Key, c.Current, c.Desired)
		}
		if len(otherConflicts) > 0 {
			b.WriteString("\nre-run with --force to overwrite the non-identity conflicts (never applies to user.signingkey).")
		}
		return nil, errors.New(b.String())
	}

	// The attestation fetch refspec (idempotent by parsed src/dst).
	p.Fetch = planFetch(env)
	return p, nil
}

// desiredKeys is the ordered set of (key, desired, current) triples for the mode. The
// current value is the repo-LOCAL one (env.Current), the scope setup writes.
func desiredKeys(env Env) []keyval {
	cur := func(k string) string { return env.Current[k] }
	var kv []keyval
	if env.SigningKey != "" {
		kv = append(kv,
			keyval{keyGPGFormat, "ssh", cur(keyGPGFormat)},
			keyval{keySigningKey, env.SigningKey, cur(keySigningKey)},
		)
	} else {
		kv = append(kv,
			keyval{keyGPGFormat, "openpgp", cur(keyGPGFormat)},
			keyval{keySigningKey, env.GPGSigningKey, cur(keySigningKey)},
		)
	}
	kv = append(kv, keyval{keyCommitGPGSign, "true", cur(keyCommitGPGSign)})
	if env.GitmessageExists {
		kv = append(kv, keyval{keyCommitTemplate, ".gitmessage", cur(keyCommitTemplate)})
	}
	// gpg.ssh.allowedSignersFile is SSH-mode only, and only when the file is present.
	if env.SigningKey != "" && env.AllowedSignersExists && env.AllowedSignersPath != "" {
		kv = append(kv, keyval{keyAllowedSigners, env.AllowedSignersPath, cur(keyAllowedSigners)})
	}
	return kv
}

// planFetch decides whether the attestation refspec must be appended, comparing
// PARSED refspecs (src/dst) so a +-prefixed or otherwise-equivalent existing entry is
// idempotent (SU-9). It never writes a push refspec.
func planFetch(env Env) *FetchChange {
	remote := env.Remote
	if remote == "" {
		remote = "origin"
	}
	fc := &FetchChange{Remote: remote, Refspec: AttestationRefspec}
	for _, rs := range env.RemoteFetchRefspecs {
		if refspecEquivalent(rs, AttestationRefspec) {
			fc.Already = true
			break
		}
	}
	return fc
}

// refspecEquivalent reports whether two refspecs fetch the same refs. Both are
// validated with go-git's config.RefSpec; the leading force '+' is ignored, since it
// changes only fast-forward enforcement, not WHICH refs move — so an existing
// +-variant is idempotent with the non-force one setup writes.
func refspecEquivalent(a, b string) bool {
	if config.RefSpec(a).Validate() != nil || config.RefSpec(b).Validate() != nil {
		return false
	}
	return strings.TrimPrefix(a, "+") == strings.TrimPrefix(b, "+")
}

// Apply executes the plan's writes through the git binary, skipping already-set keys
// and include-downgraded (manual) keys. It is called only for a real (non-dry-run)
// run, after Plan has validated everything.
func (p *Plan) Apply(git gitconfig.Git) error {
	for _, c := range p.Changes {
		if c.Action != ActionSet && c.Action != ActionForced {
			continue // ok / manual → nothing to write
		}
		if err := git.Set(c.Key, c.Desired); err != nil {
			return err
		}
	}
	if p.Fetch != nil && !p.Fetch.Already {
		if err := git.AddFetch(p.Fetch.Remote, p.Fetch.Refspec); err != nil {
			return err
		}
	}
	return nil
}

// ReverseCommands is the reversal receipt (SU-12): the exact commands that undo what a
// real run wrote — restore a forced key's old value, unset a newly-set key, and remove
// the appended refspec. Manual/already-set entries wrote nothing, so they are omitted.
func (p *Plan) ReverseCommands() []string {
	var out []string
	for _, c := range p.Changes {
		switch c.Action {
		case ActionSet:
			out = append(out, fmt.Sprintf("git config --unset %s", c.Key))
		case ActionForced:
			out = append(out, fmt.Sprintf("git config %s %q", c.Key, c.Current))
		}
	}
	if p.Fetch != nil && !p.Fetch.Already {
		// git treats the value as a regex; escape the '*' wildcards to match literally.
		pattern := strings.ReplaceAll(p.Fetch.Refspec, "*", `\*`)
		out = append(out, fmt.Sprintf("git config --unset remote.%s.fetch %q", p.Fetch.Remote, pattern))
	}
	return out
}

// GitCommands renders the plan as the byte-exact `git config` commands a real run would
// run — the --dry-run output IS the manual fallback (ADR-039).
func (p *Plan) GitCommands() []string {
	var out []string
	for _, c := range p.Changes {
		switch c.Action {
		case ActionSet, ActionForced, ActionManual:
			out = append(out, fmt.Sprintf("git config %s %q", c.Key, c.Desired))
		}
	}
	if p.Fetch != nil && !p.Fetch.Already {
		out = append(out, fmt.Sprintf("git config --add remote.%s.fetch %q", p.Fetch.Remote, p.Fetch.Refspec))
	}
	return out
}
