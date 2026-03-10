//go:build linux

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildLandlockRules_Empty(t *testing.T) {
	rules := BuildLandlockRules(LandlockPaths{})
	assert.Empty(t, rules)
}

func TestBuildLandlockRules_ROOnly(t *testing.T) {
	rules := BuildLandlockRules(LandlockPaths{RODirs: []string{"/usr", "/lib"}})
	assert.Len(t, rules, 1)
}

func TestBuildLandlockRules_RWOnly(t *testing.T) {
	rules := BuildLandlockRules(LandlockPaths{RWDirs: []string{"/tmp"}})
	assert.Len(t, rules, 1)
}

func TestBuildLandlockRules_Both(t *testing.T) {
	rules := BuildLandlockRules(LandlockPaths{RODirs: []string{"/usr"}, RWDirs: []string{"/tmp"}})
	assert.Len(t, rules, 2)
}

func TestBuildLandlockRules_WithExecPaths(t *testing.T) {
	rules := BuildLandlockRules(LandlockPaths{
		RODirs: []string{"/usr", "/lib"},
		RWDirs: []string{"/tmp"},
		Exec:   []string{"/usr/bin", "/bin"},
	})
	// RO rule + RW rule + exec rule = 3.
	assert.Len(t, rules, 3)
}

func TestBuildLandlockRules_NoExecRestrict(t *testing.T) {
	// Empty Exec means no exec restriction: uses RODirs/RWDirs (which include execute).
	rules := BuildLandlockRules(LandlockPaths{RODirs: []string{"/usr"}, RWDirs: []string{"/tmp"}})
	assert.Len(t, rules, 2)

	// With exec paths, same RO+RW produces 3 rules (RO + RW + exec).
	rules = BuildLandlockRules(LandlockPaths{RODirs: []string{"/usr"}, RWDirs: []string{"/tmp"}, Exec: []string{"/usr/bin"}})
	assert.Len(t, rules, 3)
}

func TestBuildLandlockRules_ExecPathsOnly(t *testing.T) {
	// No RO or RW paths, just exec paths.
	rules := BuildLandlockRules(LandlockPaths{Exec: []string{"/usr/bin"}})
	assert.Len(t, rules, 1)
}

func TestBuildLandlockRules_ROFiles(t *testing.T) {
	rules := BuildLandlockRules(LandlockPaths{
		RODirs:  []string{"/usr"},
		ROFiles: []string{"/dev/urandom", "/dev/random"},
	})
	assert.Len(t, rules, 2)
}

func TestBuildLandlockRules_RWFiles(t *testing.T) {
	rules := BuildLandlockRules(LandlockPaths{
		RWDirs:  []string{"/tmp"},
		RWFiles: []string{"/dev/null", "/dev/zero"},
	})
	assert.Len(t, rules, 2)
}

func TestBuildLandlockRules_FilesWithExec(t *testing.T) {
	rules := BuildLandlockRules(LandlockPaths{
		RODirs:  []string{"/usr"},
		ROFiles: []string{"/dev/urandom"},
		RWDirs:  []string{"/tmp"},
		RWFiles: []string{"/dev/null"},
		Exec:    []string{"/usr/bin"},
	})
	// RODirs + ROFiles + RWDirs + RWFiles + Exec = 5.
	assert.Len(t, rules, 5)
}
