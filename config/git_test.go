package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsGitWorkTree_Directory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))

	ok, err := IsGitWorkTree(dir)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestIsGitWorkTree_File(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: /some/path/.git/worktrees/foo\n"), 0o644)
	require.NoError(t, err)

	ok, err := IsGitWorkTree(dir)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestIsGitWorkTree_NonGit(t *testing.T) {
	dir := t.TempDir()

	ok, err := IsGitWorkTree(dir)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestIsGitWorkTree_Nested(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))
	nested := filepath.Join(dir, "sub", "deep")
	require.NoError(t, os.MkdirAll(nested, 0o755))

	ok, err := IsGitWorkTree(nested)
	require.NoError(t, err)
	assert.True(t, ok)
}
