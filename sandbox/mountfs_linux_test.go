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

func TestBuildMountPlan_DeviceDetection(t *testing.T) {
	cfg := &ChildConfig{
		RWFiles: []string{"/dev/null"},
		ROFiles: []string{"/dev/urandom"},
	}
	plan := buildMountPlan(cfg)

	for _, m := range plan {
		assert.True(t, m.isFile, "%s should be detected as file", m.src)
		assert.True(t, m.isDev, "%s should be detected as device", m.src)
	}
}

func TestBuildMountPlan_UserRequested(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(subDir, 0o755))

	cfg := &ChildConfig{
		ROPaths:   []string{dir, subDir},
		UserPaths: []string{subDir},
	}
	plan := buildMountPlan(cfg)

	require.Len(t, plan, 2)
	for _, m := range plan {
		if m.src == subDir {
			assert.True(t, m.userRequested, "user-specified path should be marked")
		} else {
			assert.False(t, m.userRequested, "default path should not be marked")
		}
	}
}

// TestSynthesizePasswd verifies content generation. The bind-mount step
// requires a mount namespace, so it is covered by integration tests
// (TestCurb_MountFS_UsernameNotRoot).
func TestSynthesizePasswd(t *testing.T) {
	dir := t.TempDir()
	etcDir := filepath.Join(dir, "etc")
	require.NoError(t, os.Mkdir(etcDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(etcDir, "passwd"), []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(etcDir, "group"), []byte("root:x:0:\n"), 0o644))

	cfg := &ChildConfig{
		Env: []string{"HOME=/app", "SHELL=/bin/bash", "USER=web"},
	}
	// synthesizePasswd writes .curb temp files then bind-mounts them.
	// The mount fails without a mount NS, but the temp files are written.
	_ = synthesizePasswd(cfg, dir)

	passwd, err := os.ReadFile(filepath.Join(etcDir, "passwd.curb"))
	require.NoError(t, err)
	assert.Contains(t, string(passwd), "web:x:0:0::/app:/bin/bash")
	assert.Contains(t, string(passwd), "nobody:x:65534:65534:")
	assert.NotContains(t, string(passwd), "root")
}
