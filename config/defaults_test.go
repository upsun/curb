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
	result := ExpandTildes([]string{"~/docs", "/abs/path", "relative"}, "/home/user")
	assert.Equal(t, []string{"/home/user/docs", "/abs/path", "relative"}, result)
}
