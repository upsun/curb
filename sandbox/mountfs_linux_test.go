//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildMountPlan_SortAndDedup(t *testing.T) {
	base := t.TempDir()
	dirA := filepath.Join(base, "aaa")
	dirB := filepath.Join(base, "bbb")
	require.NoError(t, os.Mkdir(dirA, 0o755))
	require.NoError(t, os.Mkdir(dirB, 0o755))

	cfg := &ChildConfig{
		ROPaths: []string{dirB, dirA},
	}
	plan := buildMountPlan(cfg)

	require.Len(t, plan, 2)
	// Shortest path first, then alphabetical for equal length.
	assert.Equal(t, dirA, plan[0].src)
	assert.Equal(t, dirB, plan[1].src)
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
	dirA := t.TempDir()
	dirB := t.TempDir()
	f := filepath.Join(dirB, "file.txt")
	require.NoError(t, os.WriteFile(f, nil, 0o644))

	cfg := &ChildConfig{
		ROPaths: []string{dirA},
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
	dirA := t.TempDir()
	dirB := t.TempDir()

	cfg := &ChildConfig{
		ROPaths:   []string{dirA, dirB},
		UserPaths: []string{dirB},
	}
	plan := buildMountPlan(cfg)

	require.Len(t, plan, 2)
	for _, m := range plan {
		if m.src == dirB {
			assert.True(t, m.userRequested, "user-specified path should be marked")
		} else {
			assert.False(t, m.userRequested, "default path should not be marked")
		}
	}
}

func TestBuildMountPlan_SubsumesChildWithSameFlags(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "file.txt")
	subDir := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(subDir, 0o755))
	require.NoError(t, os.WriteFile(f, nil, 0o644))

	cfg := &ChildConfig{
		ROPaths: []string{dir, subDir},
		ROFiles: []string{f},
	}
	plan := buildMountPlan(cfg)

	// Both subDir and f are subsumed by dir (identical RO flags).
	require.Len(t, plan, 1)
	assert.Equal(t, dir, plan[0].src)
}

func TestBuildMountPlan_KeepsChildWithDifferentFlags(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(subDir, 0o755))

	cfg := &ChildConfig{
		ROPaths: []string{dir},
		RWPaths: []string{subDir},
	}
	plan := buildMountPlan(cfg)

	// subDir has RW, parent has RO: not subsumed.
	require.Len(t, plan, 2)
}

func TestBuildMountPlan_DeviceNotSubsumed(t *testing.T) {
	cfg := &ChildConfig{
		ROPaths: []string{"/dev"},
		ROFiles: []string{"/dev/urandom"},
	}
	plan := buildMountPlan(cfg)

	// /dev/urandom is a device node and must not be subsumed (needs MS_NODEV exemption).
	var found bool
	for _, m := range plan {
		if m.src == "/dev/urandom" {
			found = true
			assert.True(t, m.isDev)
		}
	}
	assert.True(t, found, "/dev/urandom should not be subsumed")
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

	// Unmount any bind mounts before t.TempDir cleanup. No-op if mounts failed.
	t.Cleanup(func() {
		_ = syscall.Unmount(filepath.Join(etcDir, "passwd"), 0)
		_ = syscall.Unmount(filepath.Join(etcDir, "group"), 0)
	})

	cfg := &ChildConfig{
		Env: []string{"HOME=/app", "SHELL=/bin/bash", "USER=web"},
	}
	// synthesizePasswd writes temp files then bind-mounts them over the
	// targets. Without a mount NS the mounts fail and temp files remain.
	// In Docker the mounts may succeed and temp files are removed.
	_ = synthesizePasswd(cfg, dir)

	// Read from temp file if it exists (mount failed), otherwise from the
	// bind-mount target (mount succeeded, temp file was removed).
	passwdPath := filepath.Join(dir, ".synth-passwd")
	if _, err := os.Stat(passwdPath); err != nil {
		passwdPath = filepath.Join(etcDir, "passwd")
	}
	passwd, err := os.ReadFile(passwdPath)
	require.NoError(t, err)
	assert.Contains(t, string(passwd), "web:x:0:0::/app:/bin/bash")
	assert.Contains(t, string(passwd), "nobody:x:65534:65534:")
	assert.NotContains(t, string(passwd), "root")
}

func TestBuildMountPlan_SkipsRelativePaths(t *testing.T) {
	cfg := &ChildConfig{
		RWPaths: []string{"."},
	}
	plan := buildMountPlan(cfg)
	for _, m := range plan {
		assert.True(t, filepath.IsAbs(m.src), "relative path %q must not appear in mount plan", m.src)
	}
}
