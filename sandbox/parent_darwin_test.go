//go:build darwin

package sandbox

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/upsun/curb/config"
)

// requireSeatbelt skips the test if sandbox-exec is not available.
func requireSeatbelt(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not available")
	}
}

// buildCurb builds the curb binary for integration tests.
func buildCurb(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "curb")
	cmd := exec.Command("go", "build", "-o", bin, "..")
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Run(), "failed to build curb")
	return bin
}

// runCurb runs the curb binary with the given args and returns stdout+stderr.
func runCurb(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out.String(), exitErr.ExitCode()
		}
		t.Fatalf("running curb: %v", err)
	}
	return out.String(), 0
}

func TestSeatbelt_DryRun(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)
	output, code := runCurb(t, bin, "--dry-run", "--", "/bin/echo", "hello")
	assert.Equal(t, 0, code)
	assert.Contains(t, output, "seatbelt")
	assert.Contains(t, output, "sandbox-exec")
}

func TestSeatbelt_ReadDeny(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)
	// /private/etc/passwd is a default RO file. Denying it should make it inaccessible.
	_, code := runCurb(t, bin, "--read", "!/private/etc/passwd", "--", "/bin/cat", "/etc/passwd")
	assert.NotEqual(t, 0, code, "reading denied file should fail")
}

func TestSeatbelt_WriteDeny(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)
	// The temp dir is writable by default. Try writing to a system path.
	_, code := runCurb(t, bin, "--", "/usr/bin/touch", "/usr/local/testfile-curb")
	assert.NotEqual(t, 0, code, "writing to system path should fail")
}

func TestSeatbelt_ExecAllowed(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)
	output, code := runCurb(t, bin, "--", "/bin/echo", "sandbox-works")
	assert.Equal(t, 0, code)
	assert.Contains(t, output, "sandbox-works")
}

func TestSeatbelt_EnvSanitized(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)
	// SECRET_KEY should not be passed through.
	cmd := exec.Command(bin, "--", "/usr/bin/env")
	cmd.Env = append(os.Environ(), "SECRET_KEY=hidden")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run()
	assert.NotContains(t, out.String(), "SECRET_KEY=hidden")
}

func TestSeatbelt_PlanBuilder(t *testing.T) {
	requireSeatbelt(t)
	caps := ProbeAll()
	cfg := &config.Config{
		Command: []string{"/bin/echo", "test"},
	}
	plan, err := BuildPlan(cfg, caps, nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.True(t, plan.UseSeatbelt)
	assert.False(t, plan.UsePivotRoot)
	assert.False(t, plan.UseLandlock)
}

// TestSeatbelt_FSBlock verifies that the sandbox default-denies reads of paths
// that are not in the allow list.
func TestSeatbelt_FSBlock(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)

	// Write a file in the test's own temp dir. That dir is not inside the
	// curb sandbox temp dir, so the sandboxed process must not be able to
	// read it.
	secret := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(secret, []byte("topsecret"), 0o644))

	_, code := runCurb(t, bin, "--", "/bin/cat", secret)
	assert.NotEqual(t, 0, code, "reading a file outside the allow list should be denied")
}

// TestSeatbelt_ExecBlock verifies that the sandbox prevents executing binaries
// outside the configured ExecPaths.
func TestSeatbelt_ExecBlock(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)

	// Copy a compiled Mach-O binary into $TMPDIR (which is in RWPaths but not
	// in ExecPaths), then ask sh to execute it. The exec should be denied.
	// Shebang scripts are not used here because the kernel resolves the
	// interpreter before applying process-exec, so the interpreter path
	// (e.g. /bin/sh) is what gets checked, not the script path.
	_, code := runCurb(t, bin, "--", "/bin/sh", "-c",
		"cp /bin/echo $TMPDIR/myecho && $TMPDIR/myecho hello")
	assert.NotEqual(t, 0, code, "executing a binary from RWPaths but not ExecPaths should be denied")
}

// TestSeatbelt_ReadAllow verifies that --read grants access to a path that
// is not in the default allow list.
func TestSeatbelt_ReadAllow(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)

	// Create a file that is outside the default allow list.
	secret := filepath.Join(t.TempDir(), "data.txt")
	require.NoError(t, os.WriteFile(secret, []byte("allowed-content"), 0o644))

	// Without --read the sandboxed process should not be able to read it.
	_, code := runCurb(t, bin, "--", "/bin/cat", secret)
	assert.NotEqual(t, 0, code, "reading the file should fail without --read")

	// With --read pointing at the file it should succeed.
	out, code := runCurb(t, bin, "--read", secret, "--", "/bin/cat", secret)
	assert.Equal(t, 0, code, "--read should grant read access")
	assert.Contains(t, out, "allowed-content")
}

// TestSeatbelt_SubpathDeny verifies that !path exclusions deny access to
// a specific subtree even when the parent directory is in the allow list.
func TestSeatbelt_SubpathDeny(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)

	// /usr is a default ROPath. /usr/share/zoneinfo is a readable subtree.
	target := "/usr/share/zoneinfo/UTC"
	if _, err := os.Stat(target); err != nil {
		t.Skip("test requires " + target)
	}

	// Without any denial the file should be readable.
	_, code := runCurb(t, bin, "--", "/bin/cat", target)
	assert.Equal(t, 0, code, "reading a file under an allowed ROPath should succeed")

	// Denying the containing directory should block access even though /usr is allowed.
	_, code = runCurb(t, bin, "--read", "!/usr/share/zoneinfo", "--", "/bin/cat", target)
	assert.NotEqual(t, 0, code, "reading a file under a denied subpath should fail")
}

// TestSeatbelt_WriteAllowed verifies that the sandbox temp dir (exposed as
// $TMPDIR inside the sandbox) is writable and readable.
//
// Uses /bin/bash directly instead of /bin/sh: on macOS, /bin/sh is a trampoline
// that opens /private/var/select/sh to pick a variant, so it needs extra read
// and exec permissions that are beside the point of this test.
func TestSeatbelt_WriteAllowed(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)

	out, code := runCurb(t, bin, "--exec", "/bin/cat", "--", "/bin/bash", "-c",
		"echo hello > $TMPDIR/out.txt && cat $TMPDIR/out.txt")
	assert.Equal(t, 0, code, "writing to $TMPDIR should succeed")
	assert.Contains(t, out, "hello")
}

// TestSeatbelt_NetworkBlock verifies that outbound TCP connections are denied
// when no --domains flag is given.
func TestSeatbelt_NetworkBlock(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)

	// nc -z performs a TCP connect-only probe. Without --domains the sandbox
	// has no network-outbound allow rule, so the connect is denied immediately
	// by Seatbelt and nc exits non-zero.
	_, code := runCurb(t, bin, "--", "/usr/bin/nc", "-z", "8.8.8.8", "53")
	assert.NotEqual(t, 0, code, "outbound TCP should be blocked without --domains")
}

// TestSeatbelt_ExitCode verifies that the sandboxed child's exit code is
// propagated correctly by curb.
func TestSeatbelt_ExitCode(t *testing.T) {
	requireSeatbelt(t)
	bin := buildCurb(t)

	_, code := runCurb(t, bin, "--", "/bin/bash", "-c", "exit 42")
	assert.Equal(t, 42, code, "curb should propagate the child's exit code")
}
