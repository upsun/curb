//go:build linux

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildLandlockRules_Empty(t *testing.T) {
	rules := BuildLandlockRules(nil, nil, nil)
	assert.Empty(t, rules)
}

func TestBuildLandlockRules_ROOnly(t *testing.T) {
	rules := BuildLandlockRules([]string{"/usr", "/lib"}, nil, nil)
	assert.Len(t, rules, 1)
}

func TestBuildLandlockRules_RWOnly(t *testing.T) {
	rules := BuildLandlockRules(nil, []string{"/tmp"}, nil)
	assert.Len(t, rules, 1)
}

func TestBuildLandlockRules_Both(t *testing.T) {
	rules := BuildLandlockRules([]string{"/usr"}, []string{"/tmp"}, nil)
	assert.Len(t, rules, 2)
}

func TestBuildLandlockRules_WithExecPaths(t *testing.T) {
	rules := BuildLandlockRules(
		[]string{"/usr", "/lib"},
		[]string{"/tmp"},
		[]string{"/usr/bin", "/bin"},
	)
	// RO rule + RW rule + exec rule = 3.
	assert.Len(t, rules, 3)
}

func TestBuildLandlockRules_NoExecRestrict(t *testing.T) {
	// Empty execPaths means no exec restriction: uses RODirs/RWDirs (which include execute).
	rules := BuildLandlockRules([]string{"/usr"}, []string{"/tmp"}, nil)
	assert.Len(t, rules, 2)

	// With exec paths, same RO+RW produces 3 rules (RO + RW + exec).
	rules = BuildLandlockRules([]string{"/usr"}, []string{"/tmp"}, []string{"/usr/bin"})
	assert.Len(t, rules, 3)
}

func TestBuildLandlockRules_ExecPathsOnly(t *testing.T) {
	// No RO or RW paths, just exec paths.
	rules := BuildLandlockRules(nil, nil, []string{"/usr/bin"})
	assert.Len(t, rules, 1)
}
