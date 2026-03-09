package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindGitRoot_Directory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))

	root, err := FindGitRoot(dir)
	require.NoError(t, err)
	assert.Equal(t, dir, root)
}

func TestFindGitRoot_File(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: /some/path/.git/worktrees/foo\n"), 0o644)
	require.NoError(t, err)

	root, err := FindGitRoot(dir)
	require.NoError(t, err)
	assert.Equal(t, dir, root)
}

func TestFindGitRoot_NonGit(t *testing.T) {
	dir := t.TempDir()

	root, err := FindGitRoot(dir)
	require.NoError(t, err)
	assert.Equal(t, "", root)
}

func TestFindGitRoot_Nested(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))
	nested := filepath.Join(dir, "sub", "deep")
	require.NoError(t, os.MkdirAll(nested, 0o755))

	root, err := FindGitRoot(nested)
	require.NoError(t, err)
	assert.Equal(t, dir, root)
}

func TestFindGitHooksDir_Regular(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, ".git", "hooks")
	require.NoError(t, os.MkdirAll(hooksDir, 0o755))

	assert.Equal(t, hooksDir, FindGitHooksDir(dir))
}

func TestFindGitHooksDir_Worktree(t *testing.T) {
	// Simulate a worktree: .git is a file pointing to the main repo's gitdir.
	mainRepo := t.TempDir()
	mainHooks := filepath.Join(mainRepo, ".git", "hooks")
	require.NoError(t, os.MkdirAll(mainHooks, 0o755))

	worktree := t.TempDir()
	worktreeGitDir := filepath.Join(mainRepo, ".git", "worktrees", "wt")
	require.NoError(t, os.MkdirAll(worktreeGitDir, 0o755))
	err := os.WriteFile(filepath.Join(worktree, ".git"),
		[]byte("gitdir: "+worktreeGitDir+"\n"), 0o644)
	require.NoError(t, err)

	// The hooks dir should resolve to the worktree's gitdir/hooks, not the main repo.
	// Create hooks in the worktree gitdir to verify.
	wtHooks := filepath.Join(worktreeGitDir, "hooks")
	require.NoError(t, os.MkdirAll(wtHooks, 0o755))

	assert.Equal(t, wtHooks, FindGitHooksDir(worktree))
}

func TestFindGitHooksDir_NoHooksDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))

	assert.Equal(t, "", FindGitHooksDir(dir))
}

func TestFindGitHooksDir_NonGit(t *testing.T) {
	dir := t.TempDir()
	assert.Equal(t, "", FindGitHooksDir(dir))
}

func TestIsGitWorkTree_Directory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))

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
