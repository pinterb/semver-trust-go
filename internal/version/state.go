// SPDX-License-Identifier: Apache-2.0

package version

import "fmt"

// This file bridges the accepted VersionState (§7.5/ADR-029) to the ADR-036
// canonical object that StateDigest hashes. CanonicalStateMap is the single
// source of that object, so an emitter (release/v0.2) and a verifier
// (recurring, M6 Phase C) that both feed it the same authenticated state
// reproduce the same resulting_state.digest byte-for-byte (§8.1).

// GenesisIntervalID is the deterministic, opaque target-lineage identifier for a
// chain-genesis interval. Interval identities are opaque distinct strings the
// conformance suite carries by value; genesis has no predecessor to derive a
// "<from>..<to>" range from, so it is named by component and interval mode. Both
// the emitter and a verifier re-deriving the state produce this same id, so the
// genesis digest is reproducible.
func GenesisIntervalID(component, mode string) string {
	return fmt.Sprintf("interval:%s:%s:1", component, mode)
}

// CanonicalStateMap builds the ADR-036 semver-trust-version-state-json v0.2
// canonical object from the accepted, carried-forward version state — the input
// to StateDigest. component/tagPrefix identify the chain;
// predecessorStateDigest is the parent state's digest as its "sha256:<hex>"
// string, or nil at genesis (the hash-chain link). Every value is a JCS-safe
// type (StateDigest fails closed otherwise).
func CanonicalStateMap(component, tagPrefix string, st VersionState, predecessorStateDigest *string) map[string]any {
	lineage := make([]any, len(st.TargetIntervals))
	for i, id := range st.TargetIntervals {
		lineage[i] = id
	}
	iterations := make(map[string]any, len(st.Iterations))
	for level, n := range st.Iterations {
		iterations[level] = n
	}

	m := map[string]any{
		"profile":                  "semver-trust-version-state-json",
		"version":                  "0.2",
		"component":                component,
		"tag_prefix":               tagPrefix,
		"baseline":                 nil,
		"baseline_core":            st.BaselineCore,
		"target_core":              st.TargetCore,
		"target_bump":              st.TargetBump,
		"clean_accepted":           st.CleanAccepted,
		"target_lineage":           lineage,
		"iterations":               iterations,
		"pending_corrective_floor": nil,
		"predecessor_state_digest": nil,
	}
	if st.Baseline != nil {
		m["baseline"] = map[string]any{
			"name":              st.Baseline.Tag,
			"raw_ref_oid":       st.Baseline.RefOID,
			"peeled_commit_oid": st.Baseline.CommitOID,
			"source_identity":   map[string]any{"gitCommit": st.Baseline.CommitOID},
		}
	}
	if st.CorrectiveFloor != nil {
		m["pending_corrective_floor"] = *st.CorrectiveFloor
	}
	if predecessorStateDigest != nil {
		m["predecessor_state_digest"] = *predecessorStateDigest
	}
	return m
}
