// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"strings"
	"testing"
)

// cleanEligiblePolicy: threshold T2. An alice-authored (human) commit is T2, so
// effective trust meets the threshold. Meta requires T2 too, which the T2 commit
// satisfies (so the §5.4 gate does not preempt the eligibility judgment).
const cleanEligiblePolicy = `
[policy]
version   = "0.1"
threshold = "T2"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"
`

// cleanBelowThresholdPolicy: threshold T3. The same T2 commit is below it. Meta
// stays at T2 so the commit passes §5.4 (T2 >= T2) and the run reaches the
// clean-channel judgment rather than aborting.
const cleanBelowThresholdPolicy = `
[policy]
version   = "0.1"
threshold = "T3"
strategy  = "demote"

[meta]
paths          = [".semver-trust/**"]
required_level = "T2"
`

// verify surfaces clean-channel eligibility (§6.2/ADR-032) as an informational
// judgment — the target component's effective trust against the policy
// threshold — WITHOUT gating: a below-threshold run still succeeds (ADR-032
// places the threshold gate in the release decision, not verify).
func TestVerifyCleanChannelEligibility(t *testing.T) {
	t.Run("met when effective meets threshold", func(t *testing.T) {
		repo, _ := buildActorMapRepo(t, cleanEligiblePolicy)
		report, err := Verify(Options{
			RepoPath:           repo,
			To:                 "main",
			PolicyPath:         ".semver-trust/policy.toml",
			AllowedSignersPath: allowedSignersPath(t),
			VerifyTime:         pinnedEpoch,
		})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if report.CleanChannel == nil {
			t.Fatal("CleanChannel not populated")
		}
		cc := report.CleanChannel
		if !cc.Met || cc.Effective != "T2" || cc.Threshold != "T2" {
			t.Errorf("CleanChannel = %+v, want met with effective T2, threshold T2", cc)
		}
		var buf bytes.Buffer
		if err := report.WriteText(&buf); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "clean channel: threshold met") {
			t.Errorf("render missing the threshold-met line:\n%s", buf.String())
		}
	})

	t.Run("below threshold does not gate", func(t *testing.T) {
		repo, _ := buildActorMapRepo(t, cleanBelowThresholdPolicy)
		report, err := Verify(Options{
			RepoPath:           repo,
			To:                 "main",
			PolicyPath:         ".semver-trust/policy.toml",
			AllowedSignersPath: allowedSignersPath(t),
			VerifyTime:         pinnedEpoch,
		})
		// ADR-032: verify reports, it does not abort below threshold.
		if err != nil {
			t.Fatalf("verify aborted below threshold (ADR-032 keeps threshold a release-decision gate): %v", err)
		}
		if report.CleanChannel == nil {
			t.Fatal("CleanChannel not populated")
		}
		cc := report.CleanChannel
		if cc.Met || cc.Effective != "T2" || cc.Threshold != "T3" {
			t.Errorf("CleanChannel = %+v, want NOT met with effective T2, threshold T3", cc)
		}
		var buf bytes.Buffer
		if err := report.WriteText(&buf); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "clean channel: below threshold") {
			t.Errorf("render missing the below-threshold line:\n%s", buf.String())
		}
	})
}
