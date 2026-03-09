//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"net"
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
	// TUN probe child.
	if os.Getenv("_CURB_TUN_PROBE") != "" {
		RunTUNProbe()
		return
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
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
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
	_ = os.Remove(testFile)
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
	_ = os.Remove(testFile)
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
	for line := range strings.SplitSeq(outStr, "\n") {
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

// copyBinary copies an executable to a new path and preserves the execute bit.
func copyBinary(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err, "reading %s", src)
	require.NoError(t, os.WriteFile(dst, data, 0o755))
}

// TestCurb_Exec_SystemBinarySucceeds verifies that system binaries execute under exec restriction.
func TestCurb_Exec_SystemBinarySucceeds(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "/usr/bin/ls", "/usr")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected /usr/bin/ls to succeed: %s", string(out))
}

// TestCurb_Exec_DynamicLinkingWorks verifies that dynamically linked binaries work.
// The dynamic linker needs EXECUTE (loaded via open_exec), but shared libraries
// only need READ (loaded via mmap).
func TestCurb_Exec_DynamicLinkingWorks(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "ls", "/usr")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected dynamically linked ls to work: %s", string(out))
}

// TestCurb_Exec_NonSystemBinaryBlocked verifies that binaries outside exec paths are blocked.
func TestCurb_Exec_NonSystemBinaryBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	dir := t.TempDir()
	bin := filepath.Join(dir, "true")
	copyBinary(t, "/bin/true", bin)

	// Use --rw so the binary is readable, but exec restrictions should block execve().
	cmd := exec.Command(curbBin, "--rw", dir, "--", "sh", "-c", bin)
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected non-system binary to be blocked: %s", string(out))
	assert.Contains(t, string(out), "Permission denied")
}

// TestCurb_Exec_ExecFlagAllows verifies that --exec allows a specific binary.
func TestCurb_Exec_ExecFlagAllows(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	dir := t.TempDir()
	bin := filepath.Join(dir, "true")
	copyBinary(t, "/bin/true", bin)

	cmd := exec.Command(curbBin, "--rw", dir, "--exec", bin, "--", "sh", "-c", bin)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected --exec to allow binary: %s", string(out))
}

// TestCurb_Exec_NoExecRestrict verifies that --no-exec-restrict allows any binary.
func TestCurb_Exec_NoExecRestrict(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	dir := t.TempDir()
	bin := filepath.Join(dir, "true")
	copyBinary(t, "/bin/true", bin)

	cmd := exec.Command(curbBin, "--rw", dir, "--no-exec-restrict", "--", "sh", "-c", bin)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected --no-exec-restrict to allow binary: %s", string(out))
	assert.Contains(t, string(out), "curb: info: executable restrictions disabled")
}

// TestCurb_Exec_NotFoundErrors verifies that --exec with an unknown name errors.
func TestCurb_Exec_NotFoundErrors(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--exec", "nonexistent_tool_xyz", "--", "echo", "hello")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected --exec with nonexistent tool to error: %s", string(out))
	assert.Contains(t, string(out), "not found in PATH")
}

// TestCurb_Exec_WritableDirNotExecutable verifies that a writable temp dir is not executable.
func TestCurb_Exec_WritableDirNotExecutable(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	// The sandbox's TMPDIR is writable. Verify that writing a binary there
	// and trying to execute it is blocked.
	cmd := exec.Command(curbBin, "--", "sh", "-c",
		"cp /bin/true $TMPDIR/escape && chmod +x $TMPDIR/escape && $TMPDIR/escape")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected exec from writable TMPDIR to be blocked: %s", string(out))
	assert.Contains(t, string(out), "Permission denied")
}

// TestCurb_Exec_CWDNotExecutable verifies that binaries in a writable CWD are not executable.
func TestCurb_Exec_CWDNotExecutable(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	gitDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(gitDir, ".git"), 0o755))
	bin := filepath.Join(gitDir, "evil")
	copyBinary(t, "/bin/true", bin)

	// CWD is writable (git dir), but should not have execute permission.
	cmd := exec.Command(curbBin, "--", "sh", "-c", bin)
	cmd.Dir = gitDir
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected exec from writable CWD to be blocked: %s", string(out))
	assert.Contains(t, string(out), "Permission denied")
}

// requireNetNS skips the test if network namespace or TUN/TAP is unavailable.
func requireNetNS(t *testing.T) {
	t.Helper()
	requireUserNS(t)
	if testCaps.NetNS != nil {
		t.Skipf("network namespaces unavailable: %v", testCaps.NetNS)
	}
	if testCaps.TUN != nil {
		t.Skipf("TUN/TAP unavailable: %v", testCaps.TUN)
	}
}

// TestCurb_Net_NoNetworkByDefault verifies that without --allow, network is unreachable.
func TestCurb_Net_NoNetworkByDefault(t *testing.T) {
	requireUserNS(t)

	// Use a direct IP to avoid DNS issues. Without --allow, the child is in
	// an empty net namespace — no interfaces are configured.
	cmd := exec.Command(curbBin, "--no-fs-restrict", "--no-exec-restrict", "--",
		"sh", "-c", "curl -s --connect-timeout 3 http://93.184.215.14/ >/dev/null 2>&1")
	err := cmd.Run()
	require.Error(t, err, "expected curl to fail without --allow")
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	// curl exit 6 = couldn't resolve, 7 = couldn't connect, 28 = timeout.
	// Any of these indicate the network is blocked.
	code := exitErr.ExitCode()
	assert.True(t, code == 6 || code == 7 || code == 28,
		"expected curl failure exit code (6/7/28), got %d", code)
}

// TestCurb_Net_LoopbackDown verifies that localhost is also unreachable without --allow.
func TestCurb_Net_LoopbackDown(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--no-fs-restrict", "--no-exec-restrict", "--",
		"sh", "-c", "curl -s --connect-timeout 2 http://127.0.0.1/ >/dev/null 2>&1")
	err := cmd.Run()
	require.Error(t, err, "expected localhost to be unreachable without --allow")
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	code := exitErr.ExitCode()
	assert.True(t, code == 7 || code == 28,
		"expected curl failure exit code (7/28), got %d", code)
}

// TestCurb_Net_TCPForwarding verifies that TCP connections work through the netstack.
func TestCurb_Net_TCPForwarding(t *testing.T) {
	requireNetNS(t)

	// Use a well-known IP that serves HTTP. Resolve example.com from the host
	// to get a working IP, since DNS inside the sandbox may not work without
	// mount namespace support.
	ip := resolveForTest(t, "example.com")

	cmd := exec.Command(curbBin, "--allow", "*", "--no-fs-restrict", "--no-exec-restrict", "--",
		"sh", "-c", fmt.Sprintf("curl -s --connect-timeout 10 http://%s/ -H 'Host: example.com' | head -c 200", ip))
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "curl through netstack failed: %s", outStr)
	assert.Contains(t, outStr, "Example Domain", "expected example.com HTML content")
}

// TestCurb_Net_TLSWorks verifies that HTTPS connections work through the netstack.
func TestCurb_Net_TLSWorks(t *testing.T) {
	requireNetNS(t)

	// Use --resolve to avoid DNS but still validate the TLS certificate.
	ip := resolveForTest(t, "example.com")

	cmd := exec.Command(curbBin, "--allow", "*", "--no-fs-restrict", "--no-exec-restrict", "--",
		"sh", "-c", fmt.Sprintf("curl -sI --connect-timeout 10 --resolve example.com:443:%s https://example.com/ | head -1", ip))
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "HTTPS through netstack failed: %s", outStr)
	assert.Contains(t, outStr, "200", "expected HTTP 200 from HTTPS request")
}

// TestCurb_Net_NoRawSocketEscape verifies that the child cannot use raw sockets to bypass TAP.
func TestCurb_Net_NoRawSocketEscape(t *testing.T) {
	requireNetNS(t)

	cmd := exec.Command(curbBin, "--allow", "*", "--no-fs-restrict", "--no-exec-restrict", "--",
		"sh", "-c", "python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)' 2>&1; echo exit=$?")
	out, _ := cmd.CombinedOutput()
	outStr := string(out)
	// Raw sockets require CAP_NET_RAW which the child should not have
	// (AppArmor denies it, or the process lacks it in its effective set).
	// Even if the child is uid 0 in its namespace, raw sockets should fail.
	assert.True(t,
		strings.Contains(outStr, "Operation not permitted") ||
			strings.Contains(outStr, "PermissionError"),
		"expected raw socket creation to fail, got: %s", outStr)
}

// resolveForTest resolves a hostname to an IPv4 address on the host side.
func resolveForTest(t *testing.T, host string) string {
	t.Helper()
	addrs, err := net.LookupHost(host)
	require.NoError(t, err, "resolving %s from host", host)
	for _, addr := range addrs {
		if net.ParseIP(addr).To4() != nil {
			return addr
		}
	}
	t.Fatalf("no IPv4 address found for %s", host)
	return ""
}

// filterCurbOutput removes lines starting with "curb:" from output.
func filterCurbOutput(s string) string {
	var lines []string
	for line := range strings.SplitSeq(s, "\n") {
		if !strings.HasPrefix(line, "curb:") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}
