// SPDX-License-Identifier: Apache-2.0

package trust

import "fmt"

// Strategy is the §6.3 enforcement strategy applied when evidence does not
// support the claimed bump at the computed risk.
type Strategy uint8

const (
	// StrategyDemote keeps the semantically correct bump but confines the
	// release to the pre-release channel until evidence accumulates
	// (RECOMMENDED, §6.3).
	StrategyDemote Strategy = iota
	// StrategyInflate escalates the bump so default-range consumers do not
	// auto-adopt.
	StrategyInflate
)

// ParseStrategy parses the §9 strategy vocabulary ("demote", "inflate").
func ParseStrategy(s string) (Strategy, error) {
	switch s {
	case "demote":
		return StrategyDemote, nil
	case "inflate":
		return StrategyInflate, nil
	default:
		return 0, fmt.Errorf("invalid strategy %q (want \"demote\" or \"inflate\")", s)
	}
}

// String returns the §9 form of the strategy.
func (s Strategy) String() string {
	switch s {
	case StrategyDemote:
		return "demote"
	case StrategyInflate:
		return "inflate"
	default:
		return "unknown"
	}
}
