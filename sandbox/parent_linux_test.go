//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	curbBin  string
	testCaps *Capabilities
)

func TestMain(m *testing.M) {
	// If _CURB_INIT is set, this is the re-exec'd child.
	if os.Getenv(InitEnvKey) != "" {
		ChildInit()
		os.Exit(ExitSetupFailure)
	}

	// Probe capabilities once for all tests.
	testCaps = ProbeAll()

	// Build curb binary for integration tests.
	dir, err := os.MkdirTemp("", "curb-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		os.Exit(1)
	}

	curbBin = filepath.Join(dir, "curb")
	cmd := exec.Command("go", "build", "-o", curbBin)
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build: %v\n%s\n", err, out)
		os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func requireUserNS(t *testing.T) {
	t.Helper()
	if testCaps.UserNS != nil {
		t.Skipf("user namespaces unavailable: %v", testCaps.UserNS)
	}
}

func TestChildConfig_Serialization(t *testing.T) {
	cfg := ChildConfig{
		Command:        []string{"/bin/echo", "hello"},
		Env:            []string{"PATH=/usr/bin", "HOME=/tmp"},
		ROPaths:        []string{"/usr", "/lib"},
		NetEnabled:     true,
		AllowedDomains: []string{"example.com"},
		TempDir:        "/tmp/curb-test",
		CWD:            "/home/test",
	}

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	var decoded ChildConfig
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, cfg, decoded)
}

func TestResolveEnv(t *testing.T) {
	t.Setenv("CURB_TEST_VAR", "test_value")

	plan := &SandboxPlan{
		EnvSet: map[string]string{
			"HOME": "/tmp",
			"PATH": "/usr/bin",
		},
		EnvPassthrough: []string{"CURB_TEST_VAR"},
	}

	env := plan.resolveEnv()
	assert.Contains(t, env, "HOME=/tmp")
	assert.Contains(t, env, "PATH=/usr/bin")
	assert.Contains(t, env, "CURB_TEST_VAR=test_value")
}

func TestResolveEnv_ExplicitOverridesPassthrough(t *testing.T) {
	t.Setenv("HOME", "/original")

	plan := &SandboxPlan{
		EnvSet: map[string]string{
			"HOME": "/override",
		},
		EnvPassthrough: []string{"HOME"},
	}

	env := plan.resolveEnv()
	assert.Contains(t, env, "HOME=/override")
	assert.NotContains(t, env, "HOME=/original")
}

func TestResolveEnv_FiltersInternalVars(t *testing.T) {
	t.Setenv(InitEnvKey, "1")
	t.Setenv("_CURB_INTERNAL", "secret")

	plan := &SandboxPlan{
		EnvSet:         map[string]string{"HOME": "/tmp"},
		EnvPassthrough: []string{InitEnvKey, "_CURB_INTERNAL", "PATH"},
	}

	env := plan.resolveEnv()
	for _, e := range env {
		assert.False(t, strings.HasPrefix(e, InitEnvKey+"="), "_CURB_INIT must not appear in env")
		assert.False(t, strings.HasPrefix(e, "_CURB_INTERNAL="), "_CURB_ vars must not appear in env")
	}
}

func TestResolveEnv_PassthroughAll(t *testing.T) {
	t.Setenv("CURB_TEST_PASSALL", "yes")
	t.Setenv(InitEnvKey, "1")

	plan := &SandboxPlan{
		EnvSet:         map[string]string{"HOME": "/sandbox"},
		EnvPassthrough: []string{envPassthroughAll},
	}

	env := plan.resolveEnv()
	assert.Contains(t, env, "HOME=/sandbox", "forced vars override host")
	assert.Contains(t, env, "CURB_TEST_PASSALL=yes")
	for _, e := range env {
		assert.False(t, strings.HasPrefix(e, InitEnvKey+"="), "_CURB_INIT must not leak in passthrough-all")
		assert.False(t, strings.HasPrefix(e, "_CURB_"), "_CURB_ vars must not leak in passthrough-all")
	}
}

func TestCurb_ID(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "id")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb -- id failed: %s", string(out))
	assert.Contains(t, string(out), "uid=0")
}

func TestCurb_ExitCode(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "exit 42")
	err := cmd.Run()
	require.Error(t, err)
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, 42, exitErr.ExitCode())
}

func TestCurb_SignalDeath(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "kill -TERM $$")
	err := cmd.Run()
	require.Error(t, err)
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, 143, exitErr.ExitCode()) // 128 + SIGTERM(15)
}

func TestCurb_SetupFailureExits111(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "nonexistent-command-xyz")
	err := cmd.Run()
	require.Error(t, err)
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, ExitSetupFailure, exitErr.ExitCode())
}

func TestCurb_EnvDefault(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "env")
	cmd.Env = append(os.Environ(),
		"OPENAI_API_KEY=sk-secret",
		"AWS_SECRET_ACCESS_KEY=AKIA123",
		"GITHUB_TOKEN=ghp_secret",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb -- env failed: %s", string(out))

	envOut := string(out)
	// Secrets must not appear in the default sanitized env.
	assert.NotContains(t, envOut, "OPENAI_API_KEY=")
	assert.NotContains(t, envOut, "AWS_SECRET_ACCESS_KEY=")
	assert.NotContains(t, envOut, "GITHUB_TOKEN=")
	// _CURB_INIT must not leak.
	assert.NotContains(t, envOut, InitEnvKey+"=")
	// Forced vars must be present.
	assert.Contains(t, envOut, "HOME=")
	assert.Contains(t, envOut, "PATH=")
	assert.Contains(t, envOut, "TMPDIR=")
	assert.Contains(t, envOut, "SHELL=/bin/sh")
}

func TestCurb_EnvPassthroughName(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--env", "MY_CUSTOM_VAR", "--", "env")
	cmd.Env = append(os.Environ(), "MY_CUSTOM_VAR=hello123")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb --env MY_CUSTOM_VAR -- env failed: %s", string(out))
	assert.Contains(t, string(out), "MY_CUSTOM_VAR=hello123")
}

func TestCurb_EnvSetExplicit(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--env", "DB_URL=postgres://localhost/test", "--", "env")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb --env DB_URL=... -- env failed: %s", string(out))
	assert.Contains(t, string(out), "DB_URL=postgres://localhost/test")
}

func TestCurb_EnvPassthroughAll(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--env-passthrough", "--", "env")
	cmd.Env = append(os.Environ(), "CUSTOM_HOST_VAR=visible")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb --env-passthrough -- env failed: %s", string(out))

	envOut := string(out)
	assert.Contains(t, envOut, "CUSTOM_HOST_VAR=visible")
	// Forced vars still override host values.
	assert.Contains(t, envOut, "SHELL=/bin/sh")
	// _CURB_INIT must not leak even with passthrough.
	assert.NotContains(t, envOut, InitEnvKey+"=")
}

func TestCurb_EnvPassthroughWarning(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--env-passthrough", "--", "true")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb --env-passthrough -- true failed: %s", string(out))
	assert.Contains(t, string(out), "curb: warning: --env-passthrough passes entire host environment to child")
}

func TestCurb_EnvSafePassthrough(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "env")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "TZ=UTC", "LANG=en_US.UTF-8")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb -- env failed: %s", string(out))

	envOut := string(out)
	assert.Contains(t, envOut, "TERM=xterm-256color")
	assert.Contains(t, envOut, "TZ=UTC")
	assert.Contains(t, envOut, "LANG=en_US.UTF-8")
}

func TestCurb_EnvOnlyExpectedVars(t *testing.T) {
	requireUserNS(t)

	// Run with a controlled environment to verify only expected vars appear.
	cmd := exec.Command(curbBin, "--", "env")
	// Minimal host env: just PATH (needed to find env binary) and a secret.
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"SECRET_TOKEN=should-not-appear",
		"TERM=dumb",
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb -- env failed: %s", string(out))

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	allowed := map[string]bool{
		"HOME": true, "TMPDIR": true, "PATH": true, "SHELL": true,
		"TERM": true, "COLORTERM": true, "LANG": true, "LC_ALL": true,
		"LC_CTYPE": true, "TZ": true, "USER": true, "LOGNAME": true,
	}
	for _, line := range lines {
		name, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		assert.True(t, allowed[name], "unexpected env var in default mode: %s", name)
	}
}

func requireLandlock(t *testing.T) {
	t.Helper()
	if testCaps.LandlockABI == 0 {
		t.Skip("Landlock not available")
	}
}

func requireMountOps(t *testing.T) {
	t.Helper()
	// Test if mount operations work inside a user+mount namespace.
	cmd := exec.Command(curbBin, "--", "sh", "-c", "cat /etc/resolv.conf")
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "mount operations unavailable") {
		t.Skip("mount operations unavailable (AppArmor or similar restriction)")
	}
}

// TestCurb_FS_WriteSysPathBlocked verifies that writing to a system path is blocked by Landlock.
func TestCurb_FS_WriteSysPathBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "touch /usr/bin/curb-escape-test")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected write to /usr/bin to fail: %s", string(out))
	assert.Contains(t, string(out), "Permission denied")
}

// TestCurb_FS_WriteTmpDirAllowed verifies that the sandbox TMPDIR is writable.
func TestCurb_FS_WriteTmpDirAllowed(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "touch $TMPDIR/curb-test-write && rm $TMPDIR/curb-test-write")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected TMPDIR write to succeed: %s", string(out))
}

// TestCurb_FS_WriteGitCWDAllowed verifies that CWD is writable in a git directory.
func TestCurb_FS_WriteGitCWDAllowed(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	// Create a temp dir with a .git directory to simulate a git repo.
	gitDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(gitDir, ".git"), 0o755))
	testFile := filepath.Join(gitDir, "curb-test-write")

	cmd := exec.Command(curbBin, "--", "touch", testFile)
	cmd.Dir = gitDir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected CWD write in git dir to succeed: %s", string(out))
	os.Remove(testFile)
}

// TestCurb_FS_WriteNonGitCWDBlocked verifies that CWD is read-only in a non-git directory.
func TestCurb_FS_WriteNonGitCWDBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	nonGitDir := t.TempDir()
	testFile := filepath.Join(nonGitDir, "curb-escape-test")

	cmd := exec.Command(curbBin, "--", "touch", testFile)
	cmd.Dir = nonGitDir
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected CWD write in non-git dir to fail: %s", string(out))
	assert.Contains(t, string(out), "Permission denied")
}

// TestCurb_FS_WriteHooksBlocked verifies that .git/hooks is read-only.
func TestCurb_FS_WriteHooksBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)
	requireMountOps(t)

	gitDir := t.TempDir()
	hooksDir := filepath.Join(gitDir, ".git", "hooks")
	require.NoError(t, os.MkdirAll(hooksDir, 0o755))
	hookFile := filepath.Join(hooksDir, "pre-commit")

	cmd := exec.Command(curbBin, "--", "touch", hookFile)
	cmd.Dir = gitDir
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected hooks write to fail: %s", string(out))
	assert.Contains(t, string(out), "Permission denied")
}

// TestCurb_FS_NoFSRestrict verifies that --no-fs-restrict disables filesystem enforcement.
func TestCurb_FS_NoFSRestrict(t *testing.T) {
	requireUserNS(t)

	dir := t.TempDir()
	testFile := filepath.Join(dir, "curb-nofsr-test")

	cmd := exec.Command(curbBin, "--no-fs-restrict", "--", "touch", testFile)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected --no-fs-restrict to allow writes: %s", string(out))
	os.Remove(testFile)
}

// TestCurb_FS_HiddenPath verifies that hidden paths are overmounted with empty tmpfs.
func TestCurb_FS_HiddenPath(t *testing.T) {
	requireUserNS(t)
	requireMountOps(t)

	// Create a directory to hide with content inside.
	hideDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(hideDir, "secret"), []byte("sensitive"), 0o644))

	cmd := exec.Command(curbBin, "--hide", hideDir, "--", "ls", hideDir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "ls on hidden path should succeed (shows empty tmpfs): %s", string(out))
	outStr := strings.TrimSpace(string(out))
	// Filter out warning lines.
	var lines []string
	for _, line := range strings.Split(outStr, "\n") {
		if !strings.HasPrefix(line, "curb:") {
			lines = append(lines, line)
		}
	}
	assert.Empty(t, lines, "hidden path should appear empty, got: %v", lines)
}

// TestCurb_FS_ReadSysPathAllowed verifies that system paths are readable.
func TestCurb_FS_ReadSysPathAllowed(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "cat", "/etc/hostname")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected read of /etc/hostname to succeed: %s", string(out))
}

// TestCurb_FS_PathTraversalBlocked tries to escape via symlink traversal.
func TestCurb_FS_PathTraversalBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	// Landlock follows symlinks to the real path, so a symlink pointing outside
	// an allowed path should be blocked.
	dir := t.TempDir()
	symlink := filepath.Join(dir, "escape")
	require.NoError(t, os.Symlink("/etc/shadow", symlink))

	cmd := exec.Command(curbBin, "--rw", dir, "--", "cat", symlink)
	out, err := cmd.CombinedOutput()
	// /etc/shadow is only in RO paths, so reading through a symlink should still work
	// (it resolves to /etc/shadow which is under /etc, a default RO path).
	// But WRITING through a symlink to an RO path should fail.
	_ = out
	_ = err

	// Try writing through a symlink that points outside RW paths.
	writeTarget := filepath.Join(dir, "write-escape")
	tmpFile := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.WriteFile(tmpFile, []byte("original"), 0o644))
	require.NoError(t, os.Symlink(tmpFile, writeTarget))

	cmd = exec.Command(curbBin, "--rw", dir, "--", "sh", "-c", fmt.Sprintf("echo pwned > %s", writeTarget))
	out, err = cmd.CombinedOutput()
	require.Error(t, err, "expected write via symlink to non-RW path to fail: %s", string(out))
}

// TestCurb_FS_WriteEtcBlocked verifies /etc is read-only.
func TestCurb_FS_WriteEtcBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "echo pwned >> /etc/passwd")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected write to /etc/passwd to fail: %s", string(out))
	assert.Contains(t, string(out), "Permission denied")
}

// TestCurb_FS_WriteHomeBlocked verifies the real home directory is not writable.
func TestCurb_FS_WriteHomeBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	testFile := filepath.Join(home, "curb-escape-test-DO-NOT-CREATE")

	cmd := exec.Command(curbBin, "--", "touch", testFile)
	out, runErr := cmd.CombinedOutput()
	require.Error(t, runErr, "expected write to real home to fail: %s", string(out))
	assert.Contains(t, string(out), "Permission denied")
}

// TestCurb_FS_ResolvConfOverridden verifies /etc/resolv.conf is overridden.
func TestCurb_FS_ResolvConfOverridden(t *testing.T) {
	requireUserNS(t)
	requireMountOps(t)

	cmd := exec.Command(curbBin, "--", "cat", "/etc/resolv.conf")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected cat resolv.conf to succeed: %s", string(out))
	assert.Contains(t, string(out), sandboxNameserver, "resolv.conf should contain sandbox nameserver")
}
