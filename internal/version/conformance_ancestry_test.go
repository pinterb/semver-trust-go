// SPDX-License-Identifier: Apache-2.0

package version

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestConformanceVersionAncestry drives the spec's version-ancestry vectors
// (§7.5, ADR-029) through SelectVersionAncestry: bootstrap or accepted-
// predecessor state selects the baseline, the signed action and bump are
// candidate facts, and the exact target core / iteration / tag / head-advance
// are derived — or a stable reason aborts.
func TestConformanceVersionAncestry(t *testing.T) {
	doc := loadAncestryVectors(t)
	seen := 0
	for _, vec := range doc.Vectors {
		if vec.Kind != "version_ancestry" {
			continue
		}
		seen++
		t.Run(vec.ID, func(t *testing.T) {
			got := SelectVersionAncestry(doc.build(t, vec.Inputs))
			e := vec.Expected
			if got.Outcome != e.Outcome {
				t.Fatalf("outcome = %s (reason %q), want %s (reason %q)", got.Outcome, got.Reason, e.Outcome, ptrStr(e.Reason))
			}
			if got.Reason != ptrStr(e.Reason) {
				t.Errorf("reason = %q, want %q", got.Reason, ptrStr(e.Reason))
			}
			if !reflect.DeepEqual(got.VersionPredecessor, e.VersionPredecessor) {
				t.Errorf("version_predecessor = %v, want %v", deref(got.VersionPredecessor), deref(e.VersionPredecessor))
			}
			if !reflect.DeepEqual(got.TargetCore, e.TargetCore) {
				t.Errorf("target_core = %v, want %v", deref(got.TargetCore), deref(e.TargetCore))
			}
			if !reflect.DeepEqual(got.Iteration, e.Iteration) {
				t.Errorf("iteration = %v, want %v", got.Iteration, e.Iteration)
			}
			if !reflect.DeepEqual(got.Version, e.Version) {
				t.Errorf("version = %v, want %v", deref(got.Version), deref(e.Version))
			}
			if got.AdvancesVersionHead != e.AdvancesVersionHead {
				t.Errorf("advances_version_head = %v, want %v", got.AdvancesVersionHead, e.AdvancesVersionHead)
			}
			if !reflect.DeepEqual(got.CorrectiveFloor, e.CorrectiveFloor) {
				t.Errorf("corrective_floor = %v, want %v", deref(got.CorrectiveFloor), deref(e.CorrectiveFloor))
			}
		})
	}
	if seen == 0 {
		t.Fatal("no version_ancestry vectors ran")
	}
}

func ptrStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
func deref(p *string) interface{} {
	if p == nil {
		return nil
	}
	return *p
}

type avDoc struct {
	SpecVersion  string                      `json:"spec_version"`
	Graphs       map[string][]avCommit       `json:"graphs"`
	RefSets      map[string]map[string]avRef `json:"ref_sets"`
	Decisions    map[string]avDecision       `json:"decisions"`
	Reevals      map[string]avReeval         `json:"target_reevaluations"`
	Bootstraps   map[string]avBootstrap      `json:"bootstraps"`
	Predecessors map[string]avSelected       `json:"predecessors"`
	Superseded   map[string]avSelected       `json:"superseded"`
	Vectors      []avVector                  `json:"vectors"`
}

type avCommit struct {
	ID      string   `json:"id"`
	Parents []string `json:"parents"`
}
type avRef struct {
	RefOID    string `json:"ref_oid"`
	CommitOID string `json:"commit_oid"`
}
type avDecision struct {
	EffectiveTrust  string `json:"effective_trust"`
	Threshold       string `json:"threshold"`
	Blast           string `json:"blast"`
	Strategy        string `json:"strategy"`
	DifferAvailable bool   `json:"differ_available"`
	SemanticFloor   string `json:"semantic_floor"`
	ClaimedBump     string `json:"claimed_bump"`
}
type avReeval struct {
	Authenticated   bool     `json:"authenticated"`
	Predecessor     string   `json:"predecessor"`
	TargetCore      string   `json:"target_core"`
	SourceIntervals []string `json:"source_intervals"`
	EffectiveTrust  string   `json:"effective_trust"`
}
type avBinding struct {
	Tag       string `json:"tag"`
	RefOID    string `json:"ref_oid"`
	CommitOID string `json:"commit_oid"`
}
type avState struct {
	Baseline        *avBinding     `json:"baseline"`
	BaselineCore    string         `json:"baseline_core"`
	TargetCore      string         `json:"target_core"`
	TargetBump      string         `json:"target_bump"`
	CleanAccepted   bool           `json:"clean_accepted"`
	TargetIntervals []string       `json:"target_intervals"`
	Iterations      map[string]int `json:"iterations"`
	CorrectiveFloor *string        `json:"corrective_floor"`
}
type avBootstrap struct {
	Authenticated bool            `json:"authenticated"`
	Repository    string          `json:"repository"`
	Component     string          `json:"component"`
	IntervalMode  string          `json:"interval_mode"`
	Boundary      *string         `json:"boundary"`
	TagPrefix     string          `json:"tag_prefix"`
	VersionPred   json.RawMessage `json:"version_predecessor"`
}
type avSelected struct {
	Accepted              bool        `json:"accepted"`
	ChainHead             bool        `json:"chain_head"`
	SourceSuccessorExists bool        `json:"source_successor_exists"`
	Repository            string      `json:"repository"`
	Component             string      `json:"component"`
	TagPrefix             string      `json:"tag_prefix"`
	To                    string      `json:"to"`
	CanonicalTags         []avBinding `json:"canonical_tags"`
	State                 avState     `json:"version_state"`
}
type avVector struct {
	ID       string     `json:"id"`
	Kind     string     `json:"kind"`
	Inputs   avInputs   `json:"inputs"`
	Expected avExpected `json:"expected"`
}
type avInputs struct {
	Authority                   string  `json:"authority"`
	Bootstrap                   *string `json:"bootstrap"`
	Predecessor                 *string `json:"predecessor"`
	Superseded                  *string `json:"superseded"`
	Action                      string  `json:"action"`
	Repository                  string  `json:"repository"`
	Component                   string  `json:"component"`
	TagPrefix                   string  `json:"tag_prefix"`
	IntervalMode                string  `json:"interval_mode"`
	Boundary                    *string `json:"boundary"`
	To                          string  `json:"to"`
	Graph                       string  `json:"graph"`
	Refs                        string  `json:"refs"`
	Decision                    string  `json:"decision"`
	TargetReevaluation          *string `json:"target_reevaluation"`
	RequestedVersionPredecessor *string `json:"requested_version_predecessor"`
	RequestedIteration          *int    `json:"requested_iteration"`
}
type avExpected struct {
	Outcome             string  `json:"outcome"`
	VersionPredecessor  *string `json:"version_predecessor"`
	TargetCore          *string `json:"target_core"`
	Iteration           *int    `json:"iteration"`
	Version             *string `json:"version"`
	AdvancesVersionHead bool    `json:"advances_version_head"`
	CorrectiveFloor     *string `json:"corrective_floor"`
	Reason              *string `json:"reason"`
}

func toBinding(b avBinding) Binding { return Binding(b) }
func toBindingPtr(b *avBinding) *Binding {
	if b == nil {
		return nil
	}
	x := Binding(*b)
	return &x
}
func toState(s avState) VersionState {
	return VersionState{
		Baseline: toBindingPtr(s.Baseline), BaselineCore: s.BaselineCore, TargetCore: s.TargetCore,
		TargetBump: s.TargetBump, CleanAccepted: s.CleanAccepted, TargetIntervals: s.TargetIntervals,
		Iterations: s.Iterations, CorrectiveFloor: s.CorrectiveFloor,
	}
}
func toSelected(s avSelected) *VersionSelected {
	tags := make([]Binding, len(s.CanonicalTags))
	for i, b := range s.CanonicalTags {
		tags[i] = toBinding(b)
	}
	return &VersionSelected{
		Accepted: s.Accepted, ChainHead: s.ChainHead, SourceSuccessorExists: s.SourceSuccessorExists,
		Repository: s.Repository, Component: s.Component, TagPrefix: s.TagPrefix, To: s.To,
		CanonicalTags: tags, State: toState(s.State),
	}
}

func (d avDoc) build(t *testing.T, in avInputs) AncestryInputs {
	t.Helper()
	graph := d.Graphs[in.Graph]
	commits := make([]AncestryCommit, len(graph))
	for i, c := range graph {
		commits[i] = AncestryCommit(c)
	}
	refs := map[string]RefEntry{}
	for tag, r := range d.RefSets[in.Refs] {
		refs[tag] = RefEntry(r)
	}
	dec := d.Decisions[in.Decision]
	out := AncestryInputs{
		Authority: in.Authority, Action: in.Action, Repository: in.Repository, Component: in.Component,
		TagPrefix: in.TagPrefix, IntervalMode: in.IntervalMode, Boundary: in.Boundary, To: in.To,
		Graph: commits, Refs: refs,
		Decision:                    DecisionInputs(dec),
		RequestedVersionPredecessor: in.RequestedVersionPredecessor,
		RequestedIteration:          in.RequestedIteration,
	}
	if in.Bootstrap != nil {
		b := d.Bootstraps[*in.Bootstrap]
		vb := &VersionBootstrap{
			Authenticated: b.Authenticated, Repository: b.Repository, Component: b.Component,
			IntervalMode: b.IntervalMode, Boundary: b.Boundary, TagPrefix: b.TagPrefix,
		}
		if b.VersionPred != nil {
			vb.PredecessorPresent = true
			trimmed := string(b.VersionPred)
			switch {
			case trimmed == "null":
				vb.PredecessorNull = true
			case len(trimmed) > 0 && trimmed[0] == '[':
				vb.PredecessorAmbiguous = true
			default:
				var bind avBinding
				if err := json.Unmarshal(b.VersionPred, &bind); err != nil {
					t.Fatalf("bootstrap version_predecessor: %v", err)
				}
				x := toBinding(bind)
				vb.Predecessor = &x
			}
		}
		out.Bootstrap = vb
	}
	if in.Predecessor != nil {
		out.Predecessor = toSelected(d.Predecessors[*in.Predecessor])
		out.FixtureRef = *in.Predecessor
	}
	if in.Superseded != nil {
		out.Superseded = toSelected(d.Superseded[*in.Superseded])
		out.FixtureRef = *in.Superseded
	}
	if in.TargetReevaluation != nil {
		r := d.Reevals[*in.TargetReevaluation]
		out.TargetReevaluation = &TargetReevaluation{
			Authenticated: r.Authenticated, Predecessor: r.Predecessor, TargetCore: r.TargetCore,
			SourceIntervals: r.SourceIntervals, EffectiveTrust: r.EffectiveTrust,
		}
	}
	return out
}

func loadAncestryVectors(t *testing.T) avDoc {
	t.Helper()
	const name = "version-ancestry.json"
	path := os.Getenv("SEMVER_TRUST_VERSION_ANCESTRY_VECTORS")
	if path == "" {
		for _, candidate := range []string{
			filepath.Join("testdata", name),
			filepath.Join("..", "..", "conformance", "vendor", name),
		} {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}
	if path == "" {
		t.Fatalf("conformance vectors absent: conformance/vendor/%s missing (refresh via scripts/sync-conformance.py)", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading vectors %q: %v", path, err)
	}
	var doc avDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing vectors %q: %v", path, err)
	}
	return doc
}
