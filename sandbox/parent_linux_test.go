//go:build linux

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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
	// Mount probe child.
	if os.Getenv(MountProbeEnvKey) != "" {
		RunMountProbe()
		return
	}

	// Probe capabilities and network once for all tests.
	testCaps = ProbeAll()
	probeExternalHTTP()

	// Build curb binary for integration tests. Build to the project root as
	// "curb-test" so it matches the AppArmor profile (which uses alternation
	// to cover both "curb" and "curb-test").
	projRoot, err := filepath.Abs(filepath.Join(".", ".."))
	if err != nil {
		fmt.Fprintf(os.Stderr, "project root: %v\n", err)
		os.Exit(1)
	}
	curbBin = filepath.Join(projRoot, "curb-test")
	buildCmd := exec.Command("go", "build", "-o", curbBin)
	buildCmd.Dir = projRoot
	if out, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build: %v\n%s\n", err, out)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.Remove(curbBin)
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
		AllowedDomains: []string{"example.com"},
		TempDir:        "/tmp/curb-test",
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

	env := plan.ResolveEnv()
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

	env := plan.ResolveEnv()
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

	env := plan.ResolveEnv()
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

	env := plan.ResolveEnv()
	assert.Contains(t, env, "HOME=/sandbox", "forced vars override host")
	assert.Contains(t, env, "CURB_TEST_PASSALL=yes")
	for _, e := range env {
		assert.False(t, strings.HasPrefix(e, InitEnvKey+"="), "_CURB_INIT must not leak in passthrough-all")
		assert.False(t, strings.HasPrefix(e, "_CURB_"), "_CURB_ vars must not leak in passthrough-all")
	}
}

func TestResolveEnv_GlobPassthrough(t *testing.T) {
	t.Setenv("TEST_CURB_ALPHA", "a")
	t.Setenv("TEST_CURB_BETA", "b")
	t.Setenv("TEST_OTHER", "x")
	t.Setenv(InitEnvKey, "1")

	plan := &SandboxPlan{
		EnvSet:         map[string]string{"HOME": "/tmp"},
		EnvPassthrough: []string{"TEST_CURB_*"},
	}

	env := plan.ResolveEnv()
	assert.Contains(t, env, "TEST_CURB_ALPHA=a")
	assert.Contains(t, env, "TEST_CURB_BETA=b")
	assert.NotContains(t, env, "TEST_OTHER=x", "non-matching var must not appear")
}

func TestResolveEnv_GlobFiltersInternalVars(t *testing.T) {
	t.Setenv(InitEnvKey, "1")
	t.Setenv("_CURB_SECRET", "hidden")

	plan := &SandboxPlan{
		EnvPassthrough: []string{"_CURB_*"},
	}

	env := plan.ResolveEnv()
	for _, e := range env {
		assert.False(t, strings.HasPrefix(e, "_CURB_"), "glob must not leak internal _CURB_ vars")
	}
}

func TestCurb_ID(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "id")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb -- id failed: %s", string(out))
	assert.Contains(t, string(out), "uid=0")
}

// --- Landlock-only mode (no user namespaces) ---

// noUserNSEnv returns the test environment with user NS disabled.
func noUserNSEnv() []string {
	return append(os.Environ(), TestNoUserNSEnvKey+"=1")
}

func TestCurb_LandlockOnly_BasicExec(t *testing.T) {
	requireLandlock(t)
	cmd := exec.Command(curbBin, "--unrestricted-net", "--", "id")
	cmd.Env = noUserNSEnv()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb landlock-only basic exec failed: %s", string(out))
	// Without user NS, uid is the real user, not 0.
	assert.Contains(t, string(out), fmt.Sprintf("uid=%d", os.Getuid()))
}

func TestCurb_LandlockOnly_WriteSysPathBlocked(t *testing.T) {
	requireLandlock(t)
	cmd := exec.Command(curbBin, "--unrestricted-net", "--", "sh", "-c", "touch /usr/bin/curb-escape-test")
	cmd.Env = noUserNSEnv()
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected write to /usr/bin to be blocked")
	assertAccessDenied(t, string(out), "write to /usr/bin")
}

func TestCurb_LandlockOnly_ExitCode(t *testing.T) {
	requireLandlock(t)
	cmd := exec.Command(curbBin, "--unrestricted-net", "--", "sh", "-c", "exit 42")
	cmd.Env = noUserNSEnv()
	err := cmd.Run()
	require.Error(t, err)
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	assert.Equal(t, 42, exitErr.ExitCode())
}

func TestCurb_LandlockOnly_RequiresUnrestrictedNet(t *testing.T) {
	requireLandlock(t)
	cmd := exec.Command(curbBin, "--", "true")
	cmd.Env = noUserNSEnv()
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected error without --unrestricted-net")
	assert.Contains(t, string(out), "--unrestricted-net")
}

func TestCurb_LandlockOnly_DomainsError(t *testing.T) {
	requireLandlock(t)
	cmd := exec.Command(curbBin, "--domains", "example.com", "--", "true")
	cmd.Env = noUserNSEnv()
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected --domains to fail without user NS")
	assert.Contains(t, string(out), "--domains/--ips require user namespaces")
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
	// SHELL is a safe passthrough — only present if set on the host.
	if os.Getenv("SHELL") != "" {
		assert.Contains(t, envOut, "SHELL=")
	}
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

	cmd := exec.Command(curbBin, "--env", "*", "--", "env")
	cmd.Env = append(os.Environ(), "CUSTOM_HOST_VAR=visible")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb --env '*' -- env failed: %s", string(out))

	envOut := string(out)
	assert.Contains(t, envOut, "CUSTOM_HOST_VAR=visible")
	// SHELL is a safe passthrough — only present if set on the host.
	if os.Getenv("SHELL") != "" {
		assert.Contains(t, envOut, "SHELL=")
	}
	// _CURB_INIT must not leak even with passthrough.
	assert.NotContains(t, envOut, InitEnvKey+"=")
}

func TestCurb_EnvPassthroughWarning(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--env", "*", "--", "true")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb --env '*' -- true failed: %s", string(out))
	assert.Contains(t, string(out), "curb: warning: Entire host environment passed to child (--env '*').")
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
		"IS_SANDBOX": true, "PS1": true,
	}
	for _, line := range lines {
		name, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		assert.True(t, allowed[name], "unexpected env var in default mode: %s", name)
	}
}

func TestCurb_PS1(t *testing.T) {
	requireUserNS(t)

	// PS1 env var is set for all commands.
	cmd := exec.Command(curbBin, "--", "env")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb -- env failed: %s", string(out))

	envOut := string(out)
	assert.Contains(t, envOut, "PS1=")
	for line := range strings.SplitSeq(envOut, "\n") {
		if strings.HasPrefix(line, "PS1=") {
			assert.Contains(t, line, "(curb)")
		}
	}
}

// TestCurb_EnvLeak_ProcEnviron tries to read /proc/[pid]/environ of the parent
// process to bypass env sanitization. The user namespace blocks ptrace-guarded
// access to processes outside the namespace, so the parent's env is unreadable.
func TestCurb_EnvLeak_ProcEnviron(t *testing.T) {
	requireUserNS(t)

	// Pass a secret in the parent environment; the child should not be able
	// to recover it by reading the parent's /proc/[pid]/environ.
	ppid := os.Getpid()
	cmd := exec.Command(curbBin, "--", "sh", "-c",
		fmt.Sprintf("cat /proc/%d/environ 2>&1 || true", ppid))
	cmd.Env = append(os.Environ(), "SECRET_LEAK_TEST=hunter2")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "command failed: %s", string(out))
	assert.NotContains(t, string(out), "hunter2",
		"/proc/%d/environ leaked parent env", ppid)
}

// TestCurb_EnvLeak_ProcWalk tries to enumerate /proc/[pid] directories to find
// the parent's secret via environ files. The user namespace blocks ptrace-guarded
// access to processes outside the namespace. The child's own environ is readable
// but only contains the sanitized environment (no secrets from the parent).
func TestCurb_EnvLeak_ProcWalk(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c",
		`for f in /proc/[0-9]*/environ; do cat "$f" 2>/dev/null; done; true`)
	cmd.Env = append(os.Environ(), "SECRET_WALK_TEST=s3cret")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "walk command failed: %s", string(out))
	assert.NotContains(t, string(out), "s3cret",
		"secret from parent env leaked via /proc walk")
}

func requireLandlock(t *testing.T) {
	t.Helper()
	if testCaps.LandlockABI == 0 {
		t.Skip("Landlock not available")
	}
}

func requireMountOps(t *testing.T) {
	t.Helper()
	requireUserNS(t)
	if testCaps.MountNS != nil {
		t.Skip("mount operations unavailable (AppArmor or similar restriction)")
	}
}

// assertAccessDenied checks that the output contains an access-denied message,
// regardless of which enforcement layer produced it. Mount NS gives "Read-only
// file system" or "No such file or directory", Landlock gives "Permission
// denied", and Go's exec wrapper gives "permission denied" (lowercase).
func assertAccessDenied(t *testing.T, output, msg string) {
	t.Helper()
	lower := strings.ToLower(output)
	denied := strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "read-only file system") ||
		strings.Contains(lower, "no such file or directory") ||
		strings.Contains(lower, "operation not permitted")
	assert.True(t, denied, "%s: expected access denied, got: %s", msg, output)
}

// isSetupFailure reports whether err is a curb setup failure (exit code 111).
func isSetupFailure(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == ExitSetupFailure
}

// skipIfSetupFailed skips the test if curb exited with ExitSetupFailure (111),
// indicating an environment limitation (e.g. AppArmor blocking mount ops).
func skipIfSetupFailed(t *testing.T, err error, output string) {
	t.Helper()
	if err == nil {
		return
	}
	if isSetupFailure(err) {
		t.Skipf("curb setup failed (environment limitation): %s", strings.TrimSpace(output))
	}
}

// landlockOnlyEnv returns the test environment with mount NS disabled (Landlock-only mode).
func landlockOnlyEnv() []string {
	return append(os.Environ(), TestNoMountNSEnvKey+"=1")
}

// runOrRetryLandlockOnly runs curbBin with args. If the command fails with a
// setup failure (exit 111), it retries in Landlock-only mode (mount NS disabled).
func runOrRetryLandlockOnly(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(curbBin, args...)
	out, err := cmd.CombinedOutput()
	if isSetupFailure(err) {
		t.Log("mount NS setup failed, retrying with Landlock-only mode")
		cmd = exec.Command(curbBin, args...)
		cmd.Env = landlockOnlyEnv()
		out, err = cmd.CombinedOutput()
	}
	return out, err
}

// externalHTTPAvailable is probed once in TestMain.
var externalHTTPAvailable bool

func probeExternalHTTP() {
	conn, err := net.DialTimeout("tcp", "93.184.215.14:80", 5*time.Second)
	if err == nil {
		_ = conn.Close()
		externalHTTPAvailable = true
	}
}

// requireExternalHTTP skips the test if external HTTP connectivity is unavailable.
func requireExternalHTTP(t *testing.T) {
	t.Helper()
	if !externalHTTPAvailable {
		t.Skip("external HTTP unavailable")
	}
}

// TestCurb_FS_WriteSysPathBlocked verifies that writing to a system path is blocked by Landlock.
func TestCurb_FS_WriteSysPathBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "touch /usr/bin/curb-escape-test")
	out, err := cmd.CombinedOutput()
	skipIfSetupFailed(t, err, string(out))
	require.Error(t, err, "expected write to /usr/bin to fail: %s", string(out))
	assertAccessDenied(t, string(out), "write to /usr/bin")
}

// TestCurb_FS_WriteTmpDirAllowed verifies that the sandbox TMPDIR is writable.
func TestCurb_FS_WriteTmpDirAllowed(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "touch $TMPDIR/curb-test-write && rm $TMPDIR/curb-test-write")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected TMPDIR write to succeed: %s", string(out))
}

// TestCurb_FS_WriteCWDRequiresExplicitFlag verifies that CWD in a git dir is
// NOT writable by default, and IS writable with --write.
func TestCurb_FS_WriteCWDRequiresExplicitFlag(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	gitDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(gitDir, ".git"), 0o755))
	testFile := filepath.Join(gitDir, "curb-test-write")

	// Without --write: write should be blocked even in a git dir.
	cmd := exec.Command(curbBin, "--", "touch", testFile)
	cmd.Dir = gitDir
	out, err := cmd.CombinedOutput()
	skipIfSetupFailed(t, err, string(out))
	require.Error(t, err, "expected CWD write in git dir to fail without --write: %s", string(out))
	assertAccessDenied(t, string(out), "write to CWD in git dir")

	// With --write: write should succeed.
	cmd = exec.Command(curbBin, "--write", gitDir, "--", "touch", testFile)
	cmd.Dir = gitDir
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "expected CWD write with --write to succeed: %s", string(out))
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
	skipIfSetupFailed(t, err, string(out))
	require.Error(t, err, "expected CWD write in non-git dir to fail: %s", string(out))
	assertAccessDenied(t, string(out), "write to non-git CWD")
}

// TestCurb_FS_NoFSRestrict verifies that --write '*' disables filesystem enforcement.
func TestCurb_FS_NoFSRestrict(t *testing.T) {
	requireUserNS(t)

	dir := t.TempDir()
	testFile := filepath.Join(dir, "curb-nofsr-test")

	cmd := exec.Command(curbBin, "--write", "*", "--", "touch", testFile)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected --write '*' to allow writes: %s", string(out))
	_ = os.Remove(testFile)
}

// TestCurb_FS_HiddenPath verifies that --read '!/path' hides a sub-path.
func TestCurb_FS_HiddenPath(t *testing.T) {
	requireUserNS(t)
	requireMountOps(t)

	// Create a parent directory with content and a subdirectory to deny.
	parentDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(parentDir, "visible"), []byte("ok"), 0o644))
	subDir := filepath.Join(parentDir, "secret")
	require.NoError(t, os.Mkdir(subDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "data"), []byte("sensitive"), 0o644))

	cmd := exec.Command(curbBin, "--read", parentDir, "--read", "!"+subDir, "--", "ls", subDir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "ls on denied path should succeed (shows empty tmpfs): %s", string(out))
	outStr := filterCurbOutput(strings.TrimSpace(string(out)))
	assert.Empty(t, strings.TrimSpace(outStr), "denied path should appear empty, got: %s", outStr)
}

// TestCurb_FS_ReadSysPathAllowed verifies that system paths are readable.
func TestCurb_FS_ReadSysPathAllowed(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "cat", "/etc/hosts")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected read of /etc/hosts to succeed: %s", string(out))
}

// TestCurb_FS_PathTraversalBlocked tries to escape via symlink traversal.
func TestCurb_FS_PathTraversalBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	// Landlock follows symlinks to the real path, so a symlink pointing outside
	// an allowed path should be blocked.
	dir := t.TempDir()
	symlink := filepath.Join(dir, "escape")
	require.NoError(t, os.Symlink("/etc/passwd", symlink))

	cmd := exec.Command(curbBin, "--write", dir, "--", "cat", symlink)
	out, err := cmd.CombinedOutput()
	// /etc/passwd is a default RO file, so reading through a symlink should still work.
	// But WRITING through a symlink to an RO path should fail.
	_ = out
	_ = err

	// Try writing through a symlink that points outside RW paths.
	writeTarget := filepath.Join(dir, "write-escape")
	tmpFile := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.WriteFile(tmpFile, []byte("original"), 0o644))
	require.NoError(t, os.Symlink(tmpFile, writeTarget))

	cmd = exec.Command(curbBin, "--write", dir, "--", "sh", "-c", fmt.Sprintf("echo pwned > %s", writeTarget))
	out, err = cmd.CombinedOutput()
	require.Error(t, err, "expected write via symlink to non-RW path to fail: %s", string(out))
}

// TestCurb_FS_WriteEtcBlocked verifies /etc is read-only.
func TestCurb_FS_WriteEtcBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "echo pwned >> /etc/passwd")
	out, err := cmd.CombinedOutput()
	skipIfSetupFailed(t, err, string(out))
	require.Error(t, err, "expected write to /etc/passwd to fail: %s", string(out))
	assertAccessDenied(t, string(out), "write to /etc/passwd")
}

// TestCurb_FS_EtcMachineIdBlocked verifies /etc/machine-id is not in tightened defaults.
func TestCurb_FS_EtcMachineIdBlocked(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--", "cat", "/etc/machine-id")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected read of /etc/machine-id to fail: %s", string(out))
}

// TestCurb_FS_EtcRestored verifies that --read /etc re-adds the whole /etc directory.
func TestCurb_FS_EtcRestored(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	out, err := runOrRetryLandlockOnly(t, "--read", "/etc", "--", "cat", "/etc/hostname")
	require.NoError(t, err, "expected read of /etc/hostname with --read /etc to succeed: %s", string(out))
}

// TestCurb_FS_SubpathDenialEnforced verifies that --read '!/sub' denies access
// to a subdirectory of the CWD (which is allowed by default).
func TestCurb_FS_SubpathDenialEnforced(t *testing.T) {
	requireUserNS(t)
	requireMountOps(t)

	dir := t.TempDir()
	sub := filepath.Join(dir, "secret")
	require.NoError(t, os.Mkdir(sub, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "data"), []byte("sensitive"), 0o644))

	cmd := exec.Command(curbBin, "--read", "!"+sub, "--", "ls", sub)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "ls on denied sub-path should succeed (empty): %s", string(out))
	outStr := filterCurbOutput(strings.TrimSpace(string(out)))
	assert.Empty(t, strings.TrimSpace(outStr), "denied sub-path should appear empty, got: %s", outStr)
}

// TestCurb_FS_ExcludeCWDRead verifies --read '!.' blocks reading the CWD.
// Sub-path denials require mount NS (overmount); Landlock cannot enforce them.
func TestCurb_FS_ExcludeCWDRead(t *testing.T) {
	requireMountOps(t)

	dir := t.TempDir()
	testFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("secret"), 0o644))

	cmd := exec.Command(curbBin, "--read", "!.", "--", "cat", testFile)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected --read '!.' to block CWD read: %s", string(out))
}

// TestCurb_FS_NoDefaultReadBlocksCWD verifies --read '!*' also blocks the CWD.
// Sub-path denials require mount NS (overmount); Landlock cannot enforce them.
func TestCurb_FS_NoDefaultReadBlocksCWD(t *testing.T) {
	requireMountOps(t)

	dir := t.TempDir()
	testFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("secret"), 0o644))

	cmd := exec.Command(curbBin, "--read", "!*", "--read", "/etc/hosts", "--", "cat", testFile)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected --read '!*' to block CWD read: %s", string(out))
}

// TestCurb_FS_NoDefaultRead verifies --read '!*' clears all default read paths.
func TestCurb_FS_NoDefaultRead(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	// With !* and explicit /etc/hosts: reading /etc/hosts works but /usr/bin/env fails.
	out, err := runOrRetryLandlockOnly(t, "--read", "!*", "--read", "/etc/hosts", "--", "cat", "/etc/hosts")
	require.NoError(t, err, "expected --read '!*' --read /etc/hosts to allow /etc/hosts: %s", string(out))
}

// TestCurb_FS_ExcludeDefaultRead verifies --read !/etc/passwd removes it from defaults.
func TestCurb_FS_ExcludeDefaultRead(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--read", "!/etc/passwd", "--", "cat", "/etc/passwd")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected --read !/etc/passwd to block /etc/passwd: %s", string(out))
}

// TestCurb_FS_NoDefaultWrite verifies --write '!*' clears all default write paths.
func TestCurb_FS_NoDefaultWrite(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	cmd := exec.Command(curbBin, "--write", "!*", "--", "sh", "-c", "echo x > /dev/null")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected --write '!*' to block writes to /dev/null: %s", string(out))
}

// TestCurb_Exec_NoDefaultExec verifies --exec '!*' clears all default exec paths.
func TestCurb_Exec_NoDefaultExec(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	// Allow only /bin/sh but clear default exec paths. ls should fail.
	cmd := exec.Command(curbBin, "--exec", "!*", "--exec", "/bin/sh", "--", "sh", "-c", "ls /")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected --exec '!*' to block ls: %s", string(out))
}

// TestCurb_EnvExcludeSingle verifies --env '!USER' removes USER from defaults.
func TestCurb_EnvExcludeSingle(t *testing.T) {
	requireUserNS(t)

	t.Setenv("USER", "testuser")
	cmd := exec.Command(curbBin, "--env", "!USER", "--", "env")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb --env '!USER' -- env failed: %s", string(out))
	assert.NotContains(t, string(out), "USER=testuser")
}

// TestCurb_EnvExcludeAll verifies --env '!*' removes all env vars.
func TestCurb_EnvExcludeAll(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--env", "!*", "--", "/usr/bin/env")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb --env '!*' -- env failed: %s", string(out))
	// Should have no HOME, SHELL, IS_SANDBOX, or any other vars.
	assert.NotContains(t, string(out), "HOME=")
	assert.NotContains(t, string(out), "SHELL=")
	assert.NotContains(t, string(out), "PATH=")
	assert.NotContains(t, string(out), "IS_SANDBOX=")
}

// TestCurb_EnvExcludeAllThenSet verifies --env '!*' --env 'LANG' passes only LANG.
func TestCurb_EnvExcludeAllThenSet(t *testing.T) {
	requireUserNS(t)

	t.Setenv("LANG", "en_US.UTF-8")
	cmd := exec.Command(curbBin, "--env", "!*", "--env", "LANG", "--", "/usr/bin/env")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb --env '!*' --env LANG -- env failed: %s", string(out))
	assert.Contains(t, string(out), "LANG=en_US.UTF-8")
	assert.NotContains(t, string(out), "HOME=")
}

// TestCurb_EnvIsSandbox verifies IS_SANDBOX=1 is set in the default environment.
func TestCurb_EnvIsSandbox(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "env")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb -- env failed: %s", string(out))
	assert.Contains(t, string(out), "IS_SANDBOX=1")
}

// TestCurb_EnvExcludeIsSandbox verifies --env '!IS_SANDBOX' removes IS_SANDBOX.
func TestCurb_EnvExcludeIsSandbox(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--env", "!IS_SANDBOX", "--", "env")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "curb --env '!IS_SANDBOX' -- env failed: %s", string(out))
	assert.NotContains(t, string(out), "IS_SANDBOX=")
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
	skipIfSetupFailed(t, runErr, string(out))
	require.Error(t, runErr, "expected write to real home to fail: %s", string(out))
	assertAccessDenied(t, string(out), "write to real home")
}

// TestCurb_FS_EnvHomeNotAutoReadable verifies that --env HOME=/path sets the
// HOME env var but does not grant filesystem access to the home directory.
func TestCurb_FS_EnvHomeNotAutoReadable(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	// Find a file that exists in the home directory.
	testFile := filepath.Join(home, ".bashrc")
	if _, statErr := os.Stat(testFile); statErr != nil {
		testFile = filepath.Join(home, ".profile")
		if _, statErr := os.Stat(testFile); statErr != nil {
			t.Skip("no .bashrc or .profile in home directory")
		}
	}

	cmd := exec.Command(curbBin, "--env", "HOME="+home, "--", "cat", testFile)
	out, runErr := cmd.CombinedOutput()
	skipIfSetupFailed(t, runErr, string(out))
	require.Error(t, runErr, "expected read of %s with --env HOME to fail: %s", testFile, string(out))
	assertAccessDenied(t, string(out), "read home with --env HOME")
}
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
	cmd := exec.Command(curbBin, "--write", dir, "--", "sh", "-c", bin)
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

	cmd := exec.Command(curbBin, "--write", dir, "--exec", bin, "--", "sh", "-c", bin)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected --exec to allow binary: %s", string(out))
}

// TestCurb_Exec_SymlinkedBinaryAllowed verifies that a symlinked binary can be
// executed when the symlink directory is in PATH and the target is elsewhere.
func TestCurb_Exec_SymlinkedBinaryAllowed(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	// Create target binary in one directory.
	targetDir := t.TempDir()
	targetBin := filepath.Join(targetDir, "mytrue")
	copyBinary(t, "/bin/true", targetBin)

	// Create symlink in a different directory.
	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "mytrue")
	require.NoError(t, os.Symlink(targetBin, link))

	// Run curb with the symlink as the command. Curb should resolve the
	// symlink and allow execution of the target.
	cmd := exec.Command(curbBin, "--read", targetDir, "--read", linkDir, "--exec", link, "--", link)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected symlinked binary to be allowed: %s", string(out))
}

// TestCurb_Exec_NoExecRestrict verifies that --exec '*' allows any binary.
func TestCurb_Exec_NoExecRestrict(t *testing.T) {
	requireUserNS(t)
	requireLandlock(t)

	dir := t.TempDir()
	bin := filepath.Join(dir, "true")
	copyBinary(t, "/bin/true", bin)

	out, err := runOrRetryLandlockOnly(t, "--write", dir, "--exec", "*", "-v", "--", "sh", "-c", bin)
	require.NoError(t, err, "expected --exec '*' to allow binary: %s", string(out))
	assert.Contains(t, string(out), "curb: info: exec: disabled (--exec '*').")
}

// TestCurb_Exec_NotFoundSkipped verifies that --exec with an unknown name
// is silently skipped (the command still runs).
func TestCurb_Exec_NotFoundSkipped(t *testing.T) {
	requireUserNS(t)

	out, err := runOrRetryLandlockOnly(t, "--exec", "nonexistent_tool_xyz", "--", "echo", "hello")
	require.NoError(t, err, "expected --exec with nonexistent tool to be skipped: %s", string(out))
	assert.Contains(t, string(out), "hello")
}

// TestCurb_Exec_WritableDirNotExecutable verifies that a writable temp dir
// is not executable under mount NS enforcement (MS_NOEXEC). Landlock
// intentionally allows exec from TMPDIR for build tool compatibility
// (go test, cargo test); see TestCurb_MountFS_ExecTmpDirBlocked for
// the mount-NS-only variant.
func TestCurb_Exec_WritableDirNotExecutable(t *testing.T) {
	requireUserNS(t)
	requireMountOps(t)

	// The sandbox's TMPDIR is writable. Verify that writing a binary there
	// and trying to execute it is blocked by MS_NOEXEC.
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

	// CWD is writable via --write, but should not have execute permission.
	cmd := exec.Command(curbBin, "--write", gitDir, "--", "sh", "-c", bin)
	cmd.Dir = gitDir
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected exec from writable CWD to be blocked: %s", string(out))
	assert.Contains(t, string(out), "Permission denied")
}

// TestCurb_Net_NoNetworkByDefault verifies that without --domains, network is unreachable.
func TestCurb_Net_NoNetworkByDefault(t *testing.T) {
	requireUserNS(t)

	// Use a direct IP to avoid DNS issues. Without --allow, the child is in
	// an empty net namespace — no interfaces are configured.
	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*", "--",
		"sh", "-c", "curl -s --connect-timeout 3 http://93.184.215.14/ >/dev/null 2>&1")
	err := cmd.Run()
	require.Error(t, err, "expected curl to fail without --domains")
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	// curl exit 6 = couldn't resolve, 7 = couldn't connect, 28 = timeout.
	// Any of these indicate the network is blocked.
	code := exitErr.ExitCode()
	assert.True(t, code == 6 || code == 7 || code == 28,
		"expected curl failure exit code (6/7/28), got %d", code)
}

// TestCurb_Net_LoopbackDown verifies that localhost is also unreachable without --domains.
func TestCurb_Net_LoopbackDown(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*", "--",
		"sh", "-c", "curl -s --connect-timeout 2 http://127.0.0.1/ >/dev/null 2>&1")
	err := cmd.Run()
	require.Error(t, err, "expected localhost to be unreachable without --domains")
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok)
	code := exitErr.ExitCode()
	assert.True(t, code == 7 || code == 28,
		"expected curl failure exit code (7/28), got %d", code)
}
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
func requirePidNS(t *testing.T) {
	t.Helper()
	requireUserNS(t)
	if testCaps.PidNS != nil {
		t.Skipf("PID namespaces unavailable: %v", testCaps.PidNS)
	}
}

// TestCurb_PidNS_Isolation verifies the sandboxed process is in a different PID namespace.
func TestCurb_PidNS_Isolation(t *testing.T) {
	requirePidNS(t)

	// Read the host PID namespace.
	hostNS, err := os.Readlink("/proc/self/ns/pid")
	require.NoError(t, err)

	cmd := exec.Command(curbBin, "--", "readlink", "/proc/self/ns/pid")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "readlink /proc/self/ns/pid failed: %s", string(out))
	childNS := strings.TrimSpace(filterCurbOutput(string(out)))
	assert.NotEqual(t, hostNS, childNS, "child should be in a different PID namespace")
}

// TestCurb_PidNS_ZombieReap verifies that the init process reaps orphaned children.
func TestCurb_PidNS_ZombieReap(t *testing.T) {
	requirePidNS(t)

	// Create orphans reparented to init and verify no new zombies appear.
	// Without a fresh /proc mount, we see host PIDs, so we compare before/after
	// counts to filter out pre-existing host zombies.
	script := `
before=$(cat /proc/[0-9]*/status 2>/dev/null | grep -c '^State:.*zombie' || echo 0)
sh -c 'sleep 0.05 & exit 0'
sh -c 'sleep 0.05 & exit 0'
sh -c 'sleep 0.05 & exit 0'
sleep 0.3
after=$(cat /proc/[0-9]*/status 2>/dev/null | grep -c '^State:.*zombie' || echo 0)
if [ "$after" -gt "$before" ]; then echo "FAIL: zombies $before -> $after"; exit 1; fi
echo OK
`
	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--read", "/proc", "--", "sh", "-c", script)
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(filterCurbOutput(string(out)))
	require.NoError(t, err, "zombie reap failed: %s", outStr)
	assert.Contains(t, outStr, "OK")
}

// TestCurb_PidNS_CleanShutdown verifies that background processes are killed
// when PID 1 exits (kernel behavior for PID namespaces).
func TestCurb_PidNS_CleanShutdown(t *testing.T) {
	requirePidNS(t)

	// The target spawns a background sleep and exits. If PID NS is active,
	// the kernel sends SIGKILL to all processes in the namespace when PID 1
	// exits — the background sleep cannot outlive the sandbox.
	// We verify the curb process exits cleanly (no hang).
	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*", "--",
		"sh", "-c", "sleep 3600 & echo done")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected clean exit despite background process: %s", string(out))
	assert.Contains(t, filterCurbOutput(string(out)), "done")
}

// TestCurb_PidNS_FreshProc verifies that with both PID NS and mount NS,
// /proc only shows the namespace's own PIDs.
func TestCurb_PidNS_FreshProc(t *testing.T) {
	requirePidNS(t)
	requireMountOps(t)

	// Mount NS is always active when FS restrictions are active, so /proc is fresh.
	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*", "--",
		"sh", "-c", "ls /proc | grep -c '^[0-9]'")
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(filterCurbOutput(string(out)))
	if err != nil {
		// Only skip for expected mount failures (hidepid, permission denied).
		if strings.Contains(string(out), "/proc mount failed") ||
			strings.Contains(string(out), "Operation not permitted") {
			t.Skipf("fresh /proc mount not available: %s", outStr)
		}
		require.NoError(t, err, "unexpected failure: %s", outStr)
	}
	// With a fresh /proc in a PID namespace, there should be very few PIDs
	// (just the init and the sh pipeline). Certainly far fewer than host PIDs.
	var count int
	_, scanErr := fmt.Sscanf(outStr, "%d", &count)
	require.NoError(t, scanErr, "unexpected output: %s", outStr)
	if count >= 50 {
		t.Skipf("/proc not freshly mounted (saw %d PIDs); mount NS enforcement likely degraded", count)
	}
	assert.Less(t, count, 10, "expected few PIDs in fresh /proc, got %d", count)
}

// --- Mount NS (pivot_root) integration tests ---
// These tests exercise the pivot_root enforcement path with Landlock disabled.

// requirePivotRoot skips the test if mount operations don't work in namespaces.
func requirePivotRoot(t *testing.T) {
	t.Helper()
	requireUserNS(t)
	if testCaps.MountNS != nil {
		t.Skipf("mount operations unavailable: %v", testCaps.MountNS)
	}
}

// mountNSEnv returns the test environment with Landlock disabled.
func mountNSEnv() []string {
	return append(os.Environ(), TestNoLandlockEnvKey+"=1")
}

// TestCurb_MountFS_ReadSysPathAllowed verifies system paths are readable under pivot_root.
func TestCurb_MountFS_ReadSysPathAllowed(t *testing.T) {
	requirePivotRoot(t)

	cmd := exec.Command(curbBin, "--", "cat", "/etc/hosts")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected read of /etc/hosts to succeed: %s", string(out))
}

// TestCurb_MountFS_WriteSysPathBlocked verifies system paths are read-only under pivot_root.
// Error is EROFS (read-only filesystem) not EACCES (permission denied).
func TestCurb_MountFS_WriteSysPathBlocked(t *testing.T) {
	requirePivotRoot(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "touch /usr/bin/curb-escape-test")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected write to /usr/bin to fail: %s", string(out))
	assert.Contains(t, string(out), "Read-only file system")
}

// TestCurb_MountFS_WriteTmpDirAllowed verifies that the sandbox TMPDIR is writable.
func TestCurb_MountFS_WriteTmpDirAllowed(t *testing.T) {
	requirePivotRoot(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "touch $TMPDIR/curb-test-write && rm $TMPDIR/curb-test-write")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected TMPDIR write to succeed: %s", string(out))
}

// TestCurb_MountFS_ExecTmpDirBlocked verifies MS_NOEXEC on writable dirs under pivot_root.
func TestCurb_MountFS_ExecTmpDirBlocked(t *testing.T) {
	requirePivotRoot(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c",
		"cp /bin/true $TMPDIR/escape && chmod +x $TMPDIR/escape && $TMPDIR/escape")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected exec from writable TMPDIR to be blocked: %s", string(out))
	assert.Contains(t, string(out), "Permission denied")
}

// TestCurb_MountFS_NonDefaultPathMissing verifies non-default paths return ENOENT.
func TestCurb_MountFS_NonDefaultPathMissing(t *testing.T) {
	requirePivotRoot(t)

	cmd := exec.Command(curbBin, "--", "cat", "/etc/machine-id")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected non-default path to fail: %s", string(out))
	assert.Contains(t, string(out), "No such file or directory")
}

// TestCurb_MountFS_DenyReadSubpath verifies --read '!/path' overmounts a subpath with empty tmpfs.
func TestCurb_MountFS_DenyReadSubpath(t *testing.T) {
	requirePivotRoot(t)

	parentDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(parentDir, "visible"), []byte("ok"), 0o644))
	hideDir := filepath.Join(parentDir, "secret")
	require.NoError(t, os.Mkdir(hideDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(hideDir, "data"), []byte("sensitive"), 0o644))

	cmd := exec.Command(curbBin, "--read", parentDir, "--read", "!"+hideDir, "--", "ls", hideDir)
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "ls on denied path should succeed (shows empty tmpfs): %s", string(out))
	outStr := filterCurbOutput(strings.TrimSpace(string(out)))
	assert.Empty(t, strings.TrimSpace(outStr), "denied path should appear empty, got: %s", outStr)
}

// TestCurb_MountFS_DenyReadFile verifies --read '!/file' overmounts a file with /dev/null.
func TestCurb_MountFS_DenyReadFile(t *testing.T) {
	requirePivotRoot(t)

	cmd := exec.Command(curbBin, "--read", "/etc", "--read", "!/etc/passwd", "--", "wc", "-c", "/etc/passwd")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	skipIfSetupFailed(t, err, string(out))
	require.NoError(t, err, "wc on denied file should succeed (reads /dev/null): %s", string(out))
	outStr := filterCurbOutput(strings.TrimSpace(string(out)))
	assert.Contains(t, outStr, "0", "denied file should have 0 bytes")
}

// TestCurb_MountFS_DenyWriteSubpath verifies --write '!/path' makes a subpath read-only.
func TestCurb_MountFS_DenyWriteSubpath(t *testing.T) {
	requirePivotRoot(t)

	parentDir := t.TempDir()
	protectedDir := filepath.Join(parentDir, "protected")
	require.NoError(t, os.Mkdir(protectedDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(protectedDir, "data"), []byte("original"), 0o644))

	cmd := exec.Command(curbBin, "--write", parentDir, "--write", "!"+protectedDir, "--",
		"sh", "-c", fmt.Sprintf("echo pwned > %s/data", protectedDir))
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected write to denied path to fail: %s", string(out))
	assert.Contains(t, string(out), "Read-only file system")
}

// TestCurb_MountFS_DenyExecSubpath verifies --exec '!/path' makes a binary non-executable.
func TestCurb_MountFS_DenyExecSubpath(t *testing.T) {
	requirePivotRoot(t)

	// Deny exec on a specific binary under /usr/bin.
	cmd := exec.Command(curbBin, "--exec", "!/usr/bin/env", "--", "/usr/bin/env", "true")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	skipIfSetupFailed(t, err, string(out))
	require.Error(t, err, "expected exec of denied binary to fail: %s", string(out))
	assertAccessDenied(t, string(out), "exec of denied binary")
}

// TestCurb_MountFS_DevNullWritable verifies /dev/null is usable as a device node.
// Regression test: MS_NODEV on the bind mount previously blocked open().
func TestCurb_MountFS_DevNullWritable(t *testing.T) {
	requirePivotRoot(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "echo test > /dev/null")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected write to /dev/null to succeed: %s", string(out))
}

// TestCurb_MountFS_DevUrandomReadable verifies /dev/urandom is usable as a device node.
func TestCurb_MountFS_DevUrandomReadable(t *testing.T) {
	requirePivotRoot(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", "head -c 1 /dev/urandom > /dev/null")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected read from /dev/urandom to succeed: %s", string(out))
}

// TestCurb_MountFS_UsernameNotRoot verifies that whoami returns the original
// username, not "root", inside the user namespace.
func TestCurb_MountFS_UsernameNotRoot(t *testing.T) {
	requirePivotRoot(t)

	cmd := exec.Command(curbBin, "--", "id", "-un")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "expected id -un to succeed: %s", string(out))
	username := filterCurbOutput(strings.TrimSpace(string(out)))
	assert.NotEqual(t, "root", username, "username should not be 'root' inside user namespace")
	expected := os.Getenv("USER")
	if expected != "" {
		assert.Equal(t, expected, username, "username should match host USER")
	}
}

// TestCurb_MountFS_WriteEtcGapBlocked verifies that unmounted gap directories
// under /etc (part of the scaffolding tmpfs, not covered by any bind mount)
// are read-only. Without the root tmpfs remount this would succeed.
func TestCurb_MountFS_WriteEtcGapBlocked(t *testing.T) {
	requirePivotRoot(t)

	cmd := exec.Command(curbBin, "--", "touch", "/etc/curb-gap-test")
	cmd.Env = mountNSEnv()
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected touch in /etc gap to fail: %s", string(out))
	assert.Contains(t, string(out), "Read-only file system")
}

// --- IPs and UnrestrictedNet integration tests ---
func TestCurb_Net_UnrestrictedNet(t *testing.T) {
	requireUserNS(t)

	// Start a test HTTP server on localhost.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nUNRESTRICTED_OK"))
			_ = conn.Close()
		}
	}()

	// No --domains or --ips needed; network access is unrestricted.
	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--unrestricted-net", "--",
		"curl", "-s", "--connect-timeout", "5", fmt.Sprintf("http://127.0.0.1:%d/", port))
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "expected curl with --unrestricted-net to succeed: %s", outStr)
	assert.Contains(t, outStr, "UNRESTRICTED_OK", "expected test server response")
}

// TestCurb_Net_UnrestrictedNetFSStillEnforced verifies that --unrestricted-net
// does not disable filesystem sandboxing.
func TestCurb_Net_UnrestrictedNetFSStillEnforced(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--unrestricted-net", "--",
		"sh", "-c", "echo test > /etc/curb-test-file 2>&1")
	out, err := cmd.CombinedOutput()
	outStr := string(out)
	require.Error(t, err, "expected write to /etc to fail: %s", outStr)
	assert.True(t,
		strings.Contains(outStr, "Read-only file system") ||
			strings.Contains(outStr, "Permission denied") ||
			strings.Contains(outStr, "No such file"),
		"expected FS restriction error, got: %s", outStr)
}
func TestCurb_Net_ValidationRejectsIPInDomains(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--domains", "192.168.1.1", "--", "true")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected --domains with IP to fail: %s", string(out))
	assert.Contains(t, string(out), "use --ips instead")
}

// TestCurb_Net_ValidationRejectsURLInDomains verifies that --domains rejects URLs.
func TestCurb_Net_ValidationRejectsURLInDomains(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--domains", "https://example.com", "--", "true")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected --domains with URL to fail: %s", string(out))
	assert.Contains(t, string(out), "looks like a URL")
}

// TestCurb_Net_UnrestrictedNetConflict verifies that --unrestricted-net conflicts with --domains/--ips.
func TestCurb_Net_UnrestrictedNetConflict(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--unrestricted-net", "--domains", "example.com", "--", "true")
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected conflict error: %s", string(out))
	assert.Contains(t, string(out), "cannot be combined")
}

// TestCurb_Net_AbstractUnixSocketEscape verifies that a sandboxed process
// cannot use abstract Unix sockets to communicate with the host. Abstract
// sockets live in the network namespace (not the filesystem), so mount NS and
// Landlock do not block them. Without net NS (--unrestricted-net), this is an
// unmitigated escape vector unless socket(AF_UNIX) is blocked via seccomp.
func TestCurb_Net_AbstractUnixSocketEscape(t *testing.T) {
	requireUserNS(t)

	// Build a helper binary that connects to an abstract Unix socket and
	// sends a message.
	helperDir := t.TempDir()
	helperSrc := filepath.Join(helperDir, "escape.go")
	require.NoError(t, os.WriteFile(helperSrc, []byte(`package main

import (
	"net"
	"os"
)

func main() {
	conn, err := net.Dial("unix", "@curb-escape-test")
	if err != nil {
		os.Stderr.WriteString("dial: " + err.Error() + "\n")
		os.Exit(1)
	}
	conn.Write([]byte("ESCAPED"))
	conn.Close()
}
`), 0o644))
	helperBin := filepath.Join(helperDir, "escape")
	build := exec.Command("go", "build", "-o", helperBin, helperSrc)
	buildOut, err := build.CombinedOutput()
	require.NoError(t, err, "build helper: %s", string(buildOut))

	// Listen on an abstract Unix socket in the host namespace.
	// Abstract sockets have no filesystem path — they bypass all
	// path-based enforcement (mount NS, Landlock).
	ln, err := net.Listen("unix", "@curb-escape-test")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	// Accept one connection in the background.
	received := make(chan string, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			received <- "accept-error"
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
	}()

	// Run the helper inside curb with --unrestricted-net (no net NS).
	cmd := exec.Command(curbBin,
		"--unrestricted-net",
		"--read", helperDir,
		"--exec", helperDir,
		"--",
		helperBin)
	out, cmdErr := cmd.CombinedOutput()
	outStr := string(out)

	// The helper should fail: seccomp blocks socket(AF_UNIX) with EPERM.
	require.Error(t, cmdErr, "expected helper to fail (seccomp should block AF_UNIX)")
	assert.Contains(t, outStr, "operation not permitted",
		"expected EPERM from seccomp, got: %s", outStr)

	// Close the listener to unblock the goroutine, then verify no data arrived.
	_ = ln.Close()
	select {
	case msg := <-received:
		if msg == "ESCAPED" {
			t.Fatalf("SECURITY: sandboxed process escaped via abstract Unix socket")
		}
	case <-time.After(time.Second):
		// Goroutine didn't send anything — expected.
	}
}

// TestCurb_Net_SeccompActiveInProxyMode verifies that seccomp blocks AF_UNIX
// even in proxy mode (default). This exercises the proxyRelayInit code path
// where the Go runtime stays alive running the accept loop after seccomp is
// installed. In proxy mode, net NS already isolates abstract sockets, but
// seccomp provides defense-in-depth.
func TestCurb_Net_SeccompActiveInProxyMode(t *testing.T) {
	requireProxyNS(t)

	// The helper binary attempts socket(AF_UNIX) — seccomp should block it.
	helperDir := t.TempDir()
	helperSrc := filepath.Join(helperDir, "unixsock.go")
	require.NoError(t, os.WriteFile(helperSrc, []byte(`package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	conn, err := net.Dial("unix", "@curb-seccomp-proxy-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket blocked: %v\n", err)
		os.Exit(1)
	}
	conn.Close()
	fmt.Fprintln(os.Stderr, "ESCAPED: socket(AF_UNIX) was not blocked")
	os.Exit(0)
}
`), 0o644))
	helperBin := filepath.Join(helperDir, "unixsock")
	build := exec.Command("go", "build", "-o", helperBin, helperSrc)
	buildOut, err := build.CombinedOutput()
	require.NoError(t, err, "build helper: %s", string(buildOut))

	// Run in default proxy mode (no --unrestricted-net).
	cmd := exec.Command(curbBin,
		"--domains", "localhost",
		"--read", helperDir,
		"--exec", helperDir,
		"--",
		helperBin)
	out, cmdErr := cmd.CombinedOutput()
	outStr := string(out)

	require.Error(t, cmdErr, "expected helper to fail (seccomp should block AF_UNIX in proxy mode)")
	assert.Contains(t, outStr, "operation not permitted",
		"expected EPERM from seccomp in proxy mode, got: %s", outStr)
}

// TestCurb_Net_SeccompBlocksSocketpair verifies that socketpair(AF_UNIX) is
// also blocked, not just socket(AF_UNIX).
func TestCurb_Net_SeccompBlocksSocketpair(t *testing.T) {
	requireUserNS(t)

	// This helper calls socketpair(AF_UNIX) via Go's net package.
	helperDir := t.TempDir()
	helperSrc := filepath.Join(helperDir, "pair.go")
	require.NoError(t, os.WriteFile(helperSrc, []byte(`package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socketpair blocked: %v\n", err)
		os.Exit(1)
	}
	syscall.Close(fds[0])
	syscall.Close(fds[1])
	fmt.Fprintln(os.Stderr, "ESCAPED: socketpair(AF_UNIX) was not blocked")
	os.Exit(0)
}
`), 0o644))
	helperBin := filepath.Join(helperDir, "pair")
	build := exec.Command("go", "build", "-o", helperBin, helperSrc)
	buildOut, err := build.CombinedOutput()
	require.NoError(t, err, "build helper: %s", string(buildOut))

	cmd := exec.Command(curbBin,
		"--unrestricted-net",
		"--read", helperDir,
		"--exec", helperDir,
		"--",
		helperBin)
	out, cmdErr := cmd.CombinedOutput()
	outStr := string(out)

	require.Error(t, cmdErr, "expected helper to fail (seccomp should block socketpair)")
	assert.Contains(t, outStr, "operation not permitted",
		"expected EPERM from seccomp on socketpair, got: %s", outStr)
}

// TestCurb_Net_AllowUnixSocketsFlag verifies that --allow-unix-sockets
// disables the seccomp filter, allowing AF_UNIX socket creation.
func TestCurb_Net_AllowUnixSocketsFlag(t *testing.T) {
	requireUserNS(t)

	// Reuse the socketpair helper — it should succeed with the flag.
	helperDir := t.TempDir()
	helperSrc := filepath.Join(helperDir, "pair.go")
	require.NoError(t, os.WriteFile(helperSrc, []byte(`package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socketpair: %v\n", err)
		os.Exit(1)
	}
	syscall.Close(fds[0])
	syscall.Close(fds[1])
	fmt.Println("OK")
}
`), 0o644))
	helperBin := filepath.Join(helperDir, "pair")
	build := exec.Command("go", "build", "-o", helperBin, helperSrc)
	buildOut, err := build.CombinedOutput()
	require.NoError(t, err, "build helper: %s", string(buildOut))

	cmd := exec.Command(curbBin,
		"--unrestricted-net",
		"--allow-unix-sockets",
		"--read", helperDir,
		"--exec", helperDir,
		"--",
		helperBin)
	out, cmdErr := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))

	require.NoError(t, cmdErr,
		"expected socketpair to succeed with --allow-unix-sockets: %s", outStr)
	assert.Contains(t, outStr, "OK")
}

// TestCurb_Pdeathsig verifies the child dies when the parent is killed.
func TestCurb_Pdeathsig(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())

	// Give the child time to start.
	time.Sleep(200 * time.Millisecond)

	parentPID := cmd.Process.Pid

	// SIGKILL the parent curb process.
	require.NoError(t, syscall.Kill(parentPID, syscall.SIGKILL))
	_ = cmd.Wait()

	// Poll for the child to die (Pdeathsig delivers SIGKILL).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// Try to signal all processes in the process group.
		// If the group is gone, Kill returns an error.
		if err := syscall.Kill(-parentPID, 0); err != nil {
			return // Process group is gone.
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Clean up any survivors.
	_ = syscall.Kill(-parentPID, syscall.SIGKILL)
	t.Fatal("child process survived parent death")
}

// TestCurb_SignalEscalation verifies a second SIGINT force-kills a
// signal-ignoring child.
func TestCurb_SignalEscalation(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", `trap "" INT TERM HUP; while true; do :; done`)
	require.NoError(t, cmd.Start())
	time.Sleep(200 * time.Millisecond)

	// First SIGINT: forwarded, but the child ignores it.
	require.NoError(t, cmd.Process.Signal(syscall.SIGINT))
	time.Sleep(100 * time.Millisecond)

	// Second SIGINT: triggers force-kill.
	require.NoError(t, cmd.Process.Signal(syscall.SIGINT))

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		// Exited as expected.
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child did not exit after signal escalation")
	}
}

// TestCurb_HUPEscalation verifies SIGHUP triggers a timed force-kill.
func TestCurb_HUPEscalation(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "sh", "-c", `trap "" INT TERM HUP; while true; do :; done`)
	require.NoError(t, cmd.Start())
	time.Sleep(200 * time.Millisecond)

	// Single SIGHUP: should trigger the 3s kill timer.
	require.NoError(t, cmd.Process.Signal(syscall.SIGHUP))

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
		// Exited as expected.
	case <-time.After(6 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child did not exit after HUP escalation")
	}
}

// TestCurb_NormalSignalNoEscalation verifies a single SIGTERM kills a
// well-behaved process normally (exit 143, not 137).
func TestCurb_NormalSignalNoEscalation(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--", "sleep", "60")
	require.NoError(t, cmd.Start())
	time.Sleep(200 * time.Millisecond)

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr)
		code := exitErr.ExitCode()
		// 143 = 128 + SIGTERM(15). Not 137 (128 + SIGKILL).
		assert.Equal(t, 143, code, "expected SIGTERM exit code, got %d", code)
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child did not exit after SIGTERM")
	}
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
