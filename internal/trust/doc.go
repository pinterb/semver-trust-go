// SPDX-License-Identifier: Apache-2.0

// Package trust implements per-commit trust level assignment: the spec §3.2
// authorship × review matrix producing the scalar T0-T3, and the §3.2/§3.3/§4.1
// classifier deriving the authorship and review classes from verified commit
// facts.
//
// The package deals only in facts that upstream verification has already
// established — the signer's identity class comes from signature verification
// against injected trust material (§4.2, ADR-018), and review facts from a
// verified review attestation (§4.3). Nothing here touches the network, a
// clock, or ambient state: classification is a pure function of its inputs.
//
// The honesty clauses are load-bearing (design record §9.6): unverifiable
// claims of human authorship are treated as absent, so every ambiguity floors
// to the agent-authored row (§3.2 note 1), and a review that cannot be
// verified end-to-end classifies as no review at all rather than a weaker
// review. The scalar is deliberately lossy — "human + none" and
// "agent + human" both map to T2; policies needing the distinction consume
// the full provenance vector in the attestation (§3.2 note 4, §8.1).
package trust
