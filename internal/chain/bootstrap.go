// SPDX-License-Identifier: Apache-2.0

// Package chain supplies the out-of-band authorities that govern a v0.10
// authenticated release chain (§5.4/§7.5, ADR-028/ADR-029): the bootstrap
// descriptor at genesis, and (later) the accepted-predecessor chain head at
// recurrence. These authorities are what let the ported interval, policy-
// transition, and version-ancestry evaluators run against real repositories;
// a run is in v0.10 mode only when such an authority is supplied.
package chain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/semver-trust/semver-trust-go/internal/version"
)

// digestRe matches the sha256:<64-hex> form the descriptor pins policy and
// trust-material digests in.
var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Binding is a tag pinned to both its raw ref OID and peeled commit OID — the
// shape the descriptor's version predecessor and boundary carry, mirroring
// version.Binding.
type Binding struct {
	Tag       string `json:"tag"`
	RefOID    string `json:"ref_oid"`
	CommitOID string `json:"commit_oid"`
}

// BoundaryDescriptor is the adoption boundary the descriptor pins: the boundary
// object id and the raw ref it must still resolve to.
type BoundaryDescriptor struct {
	OID       string `json:"oid"`
	RefTarget string `json:"ref_target"`
}

// BootstrapDescriptor is the out-of-band chain-genesis authority (§5.4/§7.5,
// ADR-028). It binds the subject, interval mode and adoption boundary, the
// active policy path/digest, the role-separated trust-material digests, the
// mandatory attestation-workflow paths, the verification/clock profiles, and
// the authenticated version predecessor the first release's version line
// continues from. It is authenticated out-of-band (LoadBootstrapDescriptor) —
// never by copying it from the repository under verification.
type BootstrapDescriptor struct {
	Repository          string              `json:"repository"`
	Component           string              `json:"component"`
	IntervalMode        string              `json:"interval_mode"` // inception | adoption
	Boundary            *BoundaryDescriptor `json:"boundary"`
	TagPrefix           string              `json:"tag_prefix"`
	PolicyPath          string              `json:"policy_path"`
	PolicyDigest        string              `json:"policy_digest"`
	VerificationProfile string              `json:"verification_profile"`
	ClockProfile        string              `json:"clock_profile"`
	TrustMaterial       map[string]string   `json:"trust_material"`
	TrustRoles          map[string]string   `json:"trust_roles"`
	MandatoryMetaPaths  []string            `json:"mandatory_meta_paths"`

	// VersionPredecessor carries the §7.5 selection, which genesis MUST bind
	// explicitly — an omitted field is rejected in validate, since null genesis
	// is never inferred. An explicit null starts a new version line, a list is a
	// rejected ambiguous selection, and an object is the binding the version
	// line continues from.
	VersionPredecessor json.RawMessage `json:"version_predecessor"`

	// authenticated records that this descriptor was supplied and validated
	// out-of-band; it is not self-asserted in the JSON.
	authenticated bool
}

// Authenticated reports whether the descriptor was authenticated out-of-band.
func (d *BootstrapDescriptor) Authenticated() bool { return d.authenticated }

// LoadBootstrapDescriptor reads and authenticates a bootstrap descriptor under
// the verifier-local-configuration model (ADR-028): the operator supplies it
// from outside the repository under verification, so the supply itself is the
// out-of-band trust. A descriptor sourced from inside repoPath is rejected —
// "copying it from the candidate repository is not out-of-band trust." The
// bytes are parsed and structurally validated; a valid load marks the
// descriptor authenticated.
//
// (Signature-under-a-verifier-pinned-authority — the second ADR-028 model — is
// a planned follow-up; this establishes the verifier-local path first.)
func LoadBootstrapDescriptor(descriptorPath, repoPath string) (*BootstrapDescriptor, error) {
	inside, err := pathInside(descriptorPath, repoPath)
	if err != nil {
		return nil, err
	}
	if inside {
		return nil, fmt.Errorf(
			"bootstrap descriptor %q is inside the repository under verification: copying it from the candidate repository is not out-of-band trust (ADR-028)",
			descriptorPath,
		)
	}

	data, err := os.ReadFile(descriptorPath)
	if err != nil {
		return nil, fmt.Errorf("bootstrap descriptor: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var d BootstrapDescriptor
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("bootstrap descriptor: parsing %q: %w", descriptorPath, err)
	}
	if err := d.validate(); err != nil {
		return nil, err
	}
	d.authenticated = true
	return &d, nil
}

func (d *BootstrapDescriptor) validate() error {
	if d.Repository == "" || d.Component == "" {
		return fmt.Errorf("bootstrap descriptor: repository and component are required")
	}
	switch d.IntervalMode {
	case "inception":
		if d.Boundary != nil {
			return fmt.Errorf("bootstrap descriptor: interval_mode inception must not declare a boundary")
		}
	case "adoption":
		if d.Boundary == nil || d.Boundary.OID == "" {
			return fmt.Errorf("bootstrap descriptor: interval_mode adoption requires a boundary with an oid")
		}
	default:
		return fmt.Errorf("bootstrap descriptor: interval_mode %q is not inception or adoption", d.IntervalMode)
	}
	if d.PolicyPath == "" {
		return fmt.Errorf("bootstrap descriptor: policy_path is required")
	}
	if !digestRe.MatchString(d.PolicyDigest) {
		return fmt.Errorf("bootstrap descriptor: policy_digest %q is not sha256:<64-hex>", d.PolicyDigest)
	}
	for path, digest := range d.TrustMaterial {
		if !digestRe.MatchString(digest) {
			return fmt.Errorf("bootstrap descriptor: trust_material[%q] digest %q is not sha256:<64-hex>", path, digest)
		}
	}
	// Genesis binds exactly one version-predecessor choice — an explicit null,
	// a rejected ambiguous list, or a well-formed binding. An omitted field is
	// not a valid selection: null genesis is never inferred (§7.5/ADR-029).
	present, _, _, _, err := d.versionPredecessor()
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("bootstrap descriptor: version_predecessor is required — bind an explicit null, a binding, or an ambiguous list; genesis never infers a null version line (§7.5/ADR-029)")
	}
	return nil
}

// versionPredecessor decodes the four-way §7.5 shape:
// (present, null, ambiguous, binding). present is false when the field is
// omitted entirely.
func (d *BootstrapDescriptor) versionPredecessor() (present, null, ambiguous bool, binding *version.Binding, err error) {
	raw := strings.TrimSpace(string(d.VersionPredecessor))
	if raw == "" {
		return false, false, false, nil, nil
	}
	switch {
	case raw == "null":
		return true, true, false, nil, nil
	case strings.HasPrefix(raw, "["):
		return true, false, true, nil, nil
	default:
		var b Binding
		bd := json.NewDecoder(strings.NewReader(raw))
		bd.DisallowUnknownFields()
		if err := bd.Decode(&b); err != nil {
			return true, false, false, nil, fmt.Errorf("bootstrap descriptor: version_predecessor: %w", err)
		}
		return true, false, false, &version.Binding{Tag: b.Tag, RefOID: b.RefOID, CommitOID: b.CommitOID}, nil
	}
}

// VersionBootstrap maps the descriptor to the §7.5 version-ancestry bootstrap
// authority (version.VersionBootstrap) the SelectVersionAncestry evaluator
// consumes.
func (d *BootstrapDescriptor) VersionBootstrap() version.VersionBootstrap {
	present, null, ambiguous, binding, _ := d.versionPredecessor()
	var boundary *string
	if d.Boundary != nil {
		oid := d.Boundary.OID
		boundary = &oid
	}
	return version.VersionBootstrap{
		Authenticated:        d.authenticated,
		Repository:           d.Repository,
		Component:            d.Component,
		IntervalMode:         d.IntervalMode,
		Boundary:             boundary,
		TagPrefix:            d.TagPrefix,
		PredecessorPresent:   present,
		PredecessorNull:      null,
		PredecessorAmbiguous: ambiguous,
		Predecessor:          binding,
	}
}

// pathInside reports whether descriptorPath resolves to a location within
// repoPath's tree (so it would be a candidate-repository copy, not out-of-band).
// Both paths are canonicalized through EvalSymlinks first, so a symlink outside
// the repository that resolves back into it cannot slip past the guard and feed
// repository-controlled bytes.
func pathInside(descriptorPath, repoPath string) (bool, error) {
	dAbs, err := canonicalPath(descriptorPath)
	if err != nil {
		return false, err
	}
	rAbs, err := canonicalPath(repoPath)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(rAbs, dAbs)
	if err != nil {
		// Different volumes (Windows) — cannot be inside.
		return false, nil //nolint:nilerr // an unrelatable path is simply not inside
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

// canonicalPath resolves p to an absolute, symlink-free path. The descriptor
// must exist (it is about to be read), so an unresolvable path is a load error.
func canonicalPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}
