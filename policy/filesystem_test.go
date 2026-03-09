//go:build linux

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildLandlockRules_Empty(t *testing.T) {
	rules := BuildLandlockRules(nil, nil)
	assert.Empty(t, rules)
}

func TestBuildLandlockRules_ROOnly(t *testing.T) {
	rules := BuildLandlockRules([]string{"/usr", "/lib"}, nil)
	assert.Len(t, rules, 1)
}

func TestBuildLandlockRules_RWOnly(t *testing.T) {
	rules := BuildLandlockRules(nil, []string{"/tmp"})
	assert.Len(t, rules, 1)
}

func TestBuildLandlockRules_Both(t *testing.T) {
	rules := BuildLandlockRules([]string{"/usr"}, []string{"/tmp"})
	assert.Len(t, rules, 2)
}
