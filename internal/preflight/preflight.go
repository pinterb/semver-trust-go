// SPDX-License-Identifier: Apache-2.0

// Package preflight runs the read-only diagnostic checks behind the `doctor`
// command: it surfaces, at authoring time, the mistakes verification would later
// abort or mis-price, using the same functions verification uses. It never writes
// (ADR-037): every check is a pure read over the repository, the policy, and this
// clone's git configuration. Each FAIL names the verify abort it preempts and the
// exact fix; the report never renders a health verdict and always ends by printing
// the real `verify` invocation — doctor is the on-ramp to verify, never a
// replacement (ADR-038).
package preflight

import (
	"strings"
	"time"

	"github.com/semver-trust/semver-trust-go/internal/chain"
	"github.com/semver-trust/semver-trust-go/internal/policy"
)

// Severity is a check outcome, worst-to-render ordering aside.
type Severity int

const (
	PASS Severity = iota
	WARN
	FAIL
	SKIP
)

func (s Severity) String() string {
	switch s {
	case PASS:
		return "PASS"
	case WARN:
		return "WARN"
	case FAIL:
		return "FAIL"
	case SKIP:
		return "SKIP"
	default:
		return "?"
	}
}

// Persona selects the check-set and maps a condition to a severity: an absent
// attestation key is correct for a contributor and a FAIL for a maintainer.
// Agent is never auto-detected — it is a contract requested explicitly, and
// restricts the run to a side-effect-free subset (ADR-037).
type Persona int

const (
	Maintainer Persona = iota
	Contributor
	Agent
)

func (p Persona) String() string {
	switch p {
	case Maintainer:
		return "maintainer"
	case Contributor:
		return "contributor"
	case Agent:
		return "agent"
	default:
		return "?"
	}
}

// Result is one check's outcome. Preempts names the verify abort a FAIL moves
// earlier (the verifier's own vocabulary, e.g. "§10 step 3"); Fix is the exact
// next command.
type Result struct {
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Preempts string   `json:"preempts,omitempty"`
	Fix      string   `json:"fix,omitempty"`
}

// Result constructors keep the check bodies terse.
func pass(msg string) Result      { return Result{Severity: PASS, Message: msg} }
func warn(msg, fix string) Result { return Result{Severity: WARN, Message: msg, Fix: fix} }
func fail(msg, preempts, fix string) Result {
	return Result{Severity: FAIL, Message: msg, Preempts: preempts, Fix: fix}
}
func skip(msg string) Result { return Result{Severity: SKIP, Message: msg} }

// Env is the shared, read-only context a check runs against. Fields are populated
// once at the command boundary; a check reads only what it needs.
type Env struct {
	Repo    string
	Persona Persona
	At      time.Time

	// Policy is the parsed working-tree policy (nil when it fails to parse — the
	// policy/parse check reports PolicyErr); PolicyRaw is its raw bytes; PolicyPath
	// is its repo-relative path.
	Policy     *policy.Policy
	PolicyRaw  []byte
	PolicyPath string
	PolicyErr  error

	// Git is this clone's configuration and environment facts, read through the
	// git binary (ADR-042).
	Git *GitConfig

	// Descriptor is the out-of-band bootstrap descriptor (--bootstrap-descriptor),
	// nil when none was supplied. chain/chain-head projects the accepted chain head
	// from its descriptor-pinned repository/component; without it that check is a
	// loud SKIP (the descriptor is the authority, ADR-027/028 — it is never CLI-
	// synthesized).
	Descriptor *chain.BootstrapDescriptor

	// Simulate inputs. Message is the commit-message content to classify (nil
	// when no --message was supplied), resolved at the command boundary from a
	// file or stdin — checks stay clock- and I/O-free.
	Staged  bool
	Commit  string
	Message []byte
}

// Check is one diagnostic. Personas lists who runs it.
type Check struct {
	ID       string
	Personas []Persona
	Run      func(*Env) Result
}

func (c Check) appliesTo(p Persona) bool {
	for _, cp := range c.Personas {
		if cp == p {
			return true
		}
	}
	return false
}

// named pairs a check id with its result for the report.
type named struct {
	ID     string `json:"id"`
	Result Result `json:"result"`
}

// Report is the outcome of a doctor run.
type Report struct {
	Persona   Persona `json:"persona"`
	Checks    []named `json:"checks"`
	VerifyCmd string  `json:"verify_command"`
}

// Run executes the checks that apply to the env's persona and returns the report,
// with the filled-in verify invocation appended.
func Run(env *Env, checks []Check) *Report {
	r := &Report{Persona: env.Persona, VerifyCmd: verifyInvocation(env)}
	for _, c := range checks {
		if !c.appliesTo(env.Persona) {
			continue
		}
		r.Checks = append(r.Checks, named{ID: c.ID, Result: c.Run(env)})
	}
	return r
}

// HasFail reports whether any check FAILed (the doctor exit signal). SKIP never
// affects it.
func (r *Report) HasFail() bool {
	for _, n := range r.Checks {
		if n.Result.Severity == FAIL {
			return true
		}
	}
	return false
}

// HasWarn reports whether any check WARNed — under --strict this also drives a
// non-zero exit.
func (r *Report) HasWarn() bool {
	for _, n := range r.Checks {
		if n.Result.Severity == WARN {
			return true
		}
	}
	return false
}

// verifyInvocation is the filled-in `verify` command doctor prints at the end:
// doctor is the on-ramp to verify, so every run points at the real gate.
func verifyInvocation(env *Env) string {
	repo := env.Repo
	if repo == "" {
		repo = "."
	}
	return "semver-trust verify --repo " + shellQuote(repo) + " --to HEAD"
}

// shellQuote makes s safe to paste into a shell. The verify invocation is
// printed, never executed, but the "print the exact invocation" contract
// requires it be copy-pasteable for repo paths with spaces or shell
// metacharacters.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if !shellSafeRune(r) {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

func shellSafeRune(r rune) bool {
	return r == '-' || r == '_' || r == '.' || r == '/' || r == '@' ||
		(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
