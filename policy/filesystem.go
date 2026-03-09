//go:build linux

package policy

import (
	"github.com/landlock-lsm/go-landlock/landlock"
)

// BuildLandlockRules constructs Landlock rules from read-only and read-write path lists.
func BuildLandlockRules(roPaths, rwPaths []string) []landlock.Rule {
	var rules []landlock.Rule
	if len(roPaths) > 0 {
		rules = append(rules, landlock.RODirs(roPaths...).IgnoreIfMissing())
	}
	if len(rwPaths) > 0 {
		rules = append(rules, landlock.RWDirs(rwPaths...).IgnoreIfMissing())
	}
	return rules
}

// EnforceLandlock applies the given Landlock rules using the best available ABI version.
func EnforceLandlock(rules []landlock.Rule) error {
	return landlock.V5.BestEffort().RestrictPaths(rules...)
}
