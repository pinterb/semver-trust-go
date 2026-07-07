// SPDX-License-Identifier: Apache-2.0

package version

import "fmt"

// MaxLevel is the highest defined trust level (§7.1: levels are 0-3).
const MaxLevel uint8 = 3

// NextIteration returns v re-cut at the same core version and trust level with
// the iteration incremented by one (§7.2: iterations increment for re-cuts at
// the same core and level). It errors if v carries no trust suffix.
func (v Version) NextIteration() (Version, error) {
	if v.Trust == nil {
		return Version{}, fmt.Errorf("version %s has no trust suffix to increment", v)
	}
	out := v
	out.Trust = &TrustSuffix{Level: v.Trust.Level, Iteration: v.Trust.Iteration + 1}
	return out, nil
}

// WithLevel returns v re-cut at the given trust level with the iteration reset
// to 1 (§7.2: a re-cut at a different level starts a new suffix, e.g. -t0.1 →
// -t2.1). level must be 0..MaxLevel. Any plain pre-release on v is cleared,
// since a trust suffix and a plain pre-release are mutually exclusive.
func (v Version) WithLevel(level uint8) (Version, error) {
	if level > MaxLevel {
		return Version{}, fmt.Errorf("trust level %d out of range; only 0-%d are defined", level, MaxLevel)
	}
	out := v
	out.Pre = nil
	out.Trust = &TrustSuffix{Level: level, Iteration: 1}
	return out, nil
}
