package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandGlobs_LiteralPaths(t *testing.T) {
	expanded := ExpandGlobs([]string{"/usr", "/etc", "/tmp"})
	assert.Equal(t, []string{"/usr", "/etc", "/tmp"}, expanded)
}

func TestExpandGlobs_StarPattern(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), nil, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.txt"), nil, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "c.log"), nil, 0o644))

	expanded := ExpandGlobs([]string{filepath.Join(dir, "*.txt")})
	assert.Len(t, expanded, 2)
	assert.Contains(t, expanded, filepath.Join(dir, "a.txt"))
	assert.Contains(t, expanded, filepath.Join(dir, "b.txt"))
}

func TestExpandGlobs_NoMatches(t *testing.T) {
	dir := t.TempDir()
	pattern := filepath.Join(dir, "*.xyz")

	expanded := ExpandGlobs([]string{pattern})
	assert.Empty(t, expanded)
}

func TestExpandGlobs_MixedLiteralAndGlob(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.csv"), nil, 0o644))

	literal := "/usr"
	glob := filepath.Join(dir, "*.csv")

	expanded := ExpandGlobs([]string{literal, glob})
	assert.Equal(t, []string{literal, filepath.Join(dir, "data.csv")}, expanded)
}

func TestExpandTildes(t *testing.T) {
	result := ExpandTildes([]string{"~", "~/docs", "/abs/path", "relative"}, "/home/user")
	assert.Equal(t, []string{"/home/user", "/home/user/docs", "/abs/path", "relative"}, result)
}

func TestDefaultEnvVars_NoSHELL(t *testing.T) {
	env := DefaultEnvVars("/tmp", "")
	_, ok := env["SHELL"]
	assert.False(t, ok, "SHELL should not be in default env vars (it is a passthrough)")
}

func TestDefaultPS1(t *testing.T) {
	tests := []struct {
		command string
		noColor bool
		contains string
		notContains string
	}{
		{"/bin/bash", false, `\[`, ""},
		{"/bin/bash", true, `\u:\w`, `\[`},
		{"/usr/bin/zsh", false, "%F{cyan}", ""},
		{"/usr/bin/zsh", true, "%n:%~", "%F"},
		{"/bin/sh", false, "(curb) $ ", ""},
		{"fish", false, "(curb) $ ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			ps1 := DefaultPS1(tt.command, tt.noColor)
			assert.Contains(t, ps1, "(curb)")
			assert.Contains(t, ps1, tt.contains)
			if tt.notContains != "" {
				assert.NotContains(t, ps1, tt.notContains)
			}
		})
	}
}

func TestParseExclusions(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		adds      []string
		removes   []string
		removeAll bool
	}{
		{"nil", nil, nil, nil, false},
		{"plain adds", []string{"/a", "/b"}, []string{"/a", "/b"}, nil, false},
		{"single remove", []string{"!/a"}, nil, []string{"/a"}, false},
		{"remove all", []string{"!*"}, nil, nil, true},
		{"remove all with adds", []string{"!*", "/a"}, []string{"/a"}, nil, true},
		{"mixed", []string{"/a", "!/b", "/c"}, []string{"/a", "/c"}, []string{"/b"}, false},
		{"escaped bang", []string{`\!path`}, []string{"!path"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adds, removes, removeAll := ParseExclusions(tt.args)
			assert.Equal(t, tt.adds, adds)
			assert.Equal(t, tt.removes, removes)
			assert.Equal(t, tt.removeAll, removeAll)
		})
	}
}

func TestApplyExclusions(t *testing.T) {
	defaults := []string{"/a", "/b", "/c"}

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"no args", nil, []string{"/a", "/b", "/c"}},
		{"add only", []string{"/d"}, []string{"/a", "/b", "/c", "/d"}},
		{"remove one", []string{"!/b"}, []string{"/a", "/c"}},
		{"remove all", []string{"!*"}, nil},
		{"remove all then add", []string{"!*", "/x"}, []string{"/x"}},
		{"remove nonexistent", []string{"!/z"}, []string{"/a", "/b", "/c"}},
		{"mixed add and remove", []string{"!/b", "/d"}, []string{"/a", "/c", "/d"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ApplyExclusions(defaults, tt.args)
			assert.Equal(t, tt.want, result)
		})
	}
}

