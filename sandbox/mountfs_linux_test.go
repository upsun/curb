//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildMountPlan_SortAndDedup(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(subDir, 0o755))

	cfg := &ChildConfig{
		ROPaths: []string{subDir, dir},
	}
	plan := buildMountPlan(cfg)

	require.Len(t, plan, 2)
	// Shortest path first.
	assert.Equal(t, dir, plan[0].src)
	assert.Equal(t, subDir, plan[1].src)
}

func TestBuildMountPlan_RWOverridesRO(t *testing.T) {
	dir := t.TempDir()

	cfg := &ChildConfig{
		ROPaths: []string{dir},
		RWPaths: []string{dir},
	}
	plan := buildMountPlan(cfg)

	require.Len(t, plan, 1)
	assert.Equal(t, dir, plan[0].src)
	assert.False(t, plan[0].readOnly, "RW should override RO")
}

func TestBuildMountPlan_ExecOverride(t *testing.T) {
	dir := t.TempDir()

	cfg := &ChildConfig{
		ROPaths:   []string{dir},
		ExecPaths: []string{dir},
	}
	plan := buildMountPlan(cfg)

	require.Len(t, plan, 1)
	assert.Equal(t, dir, plan[0].src)
	assert.False(t, plan[0].noExec, "exec path should override noExec")
}

func TestBuildMountPlan_SkipsMissing(t *testing.T) {
	dir := t.TempDir()

	cfg := &ChildConfig{
		ROPaths: []string{dir, "/nonexistent/path/xyz"},
	}
	plan := buildMountPlan(cfg)

	require.Len(t, plan, 1)
	assert.Equal(t, dir, plan[0].src)
}

func TestBuildMountPlan_NoExecRestrict(t *testing.T) {
	dir := t.TempDir()

	// When ExecPaths is empty, noExec should be false for all.
	cfg := &ChildConfig{
		ROPaths: []string{dir},
	}
	plan := buildMountPlan(cfg)

	require.Len(t, plan, 1)
	assert.False(t, plan[0].noExec, "no exec restriction means noExec=false")
}

func TestBuildMountPlan_FileDetection(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "file.txt")
	require.NoError(t, os.WriteFile(f, nil, 0o644))

	cfg := &ChildConfig{
		ROPaths: []string{dir},
		ROFiles: []string{f},
	}
	plan := buildMountPlan(cfg)

	require.Len(t, plan, 2)
	for _, m := range plan {
		if m.src == f {
			assert.True(t, m.isFile, "file should be detected as file")
		} else {
			assert.False(t, m.isFile, "dir should not be detected as file")
		}
	}
}
