//go:build linux

package sandbox

import (
	"fmt"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireProxyNS skips the test if network namespaces are unavailable.
// Unlike requireNetNS, does NOT require TUN/TAP (proxy-only mode needs only net NS).
func requireProxyNS(t *testing.T) {
	t.Helper()
	requireUserNS(t)
	if testCaps.NetNS != nil {
		t.Skipf("network namespaces unavailable: %v", testCaps.NetNS)
	}
}

// TestCurb_Proxy_CurlAllowed tests that curl to an allowed domain works through the proxy.
func TestCurb_Proxy_CurlAllowed(t *testing.T) {
	requireProxyNS(t)

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--domains", "example.com",
		"--", "sh", "-c", "curl -sf --connect-timeout 10 https://example.com/ | head -c 200")
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "curl to allowed domain failed: %s", outStr)
	assert.Contains(t, outStr, "Example Domain", "expected example.com HTML content")
}

// TestCurb_Proxy_CurlBlocked tests that curl to a non-allowed domain fails through the proxy.
func TestCurb_Proxy_CurlBlocked(t *testing.T) {
	requireProxyNS(t)

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--domains", "example.com",
		"--", "sh", "-c", "curl -sf --connect-timeout 10 https://blocked.example.org/ 2>&1; echo exit=$?")
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	// curl should fail (non-zero exit) because the proxy returns 403.
	_ = err
	assert.Contains(t, outStr, "exit=", "expected curl exit code in output")
	assert.NotContains(t, outStr, "exit=0", "curl to blocked domain should fail")
}

// TestCurb_Proxy_NoProxyNoNetwork verifies that programs ignoring proxy env get no network.
func TestCurb_Proxy_NoProxyNoNetwork(t *testing.T) {
	requireProxyNS(t)

	// python3 with socket.connect ignores HTTPS_PROXY — it should get connection refused
	// (loopback is up but only the proxy port is listening).
	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--domains", "example.com",
		"--", "sh", "-c",
		"python3 -c \"import socket; s=socket.socket(); s.settimeout(3); s.connect(('93.184.215.14', 80))\" 2>&1; echo exit=$?")
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	_ = err
	// Should fail: no route to 93.184.215.14 in the empty net NS.
	assert.Contains(t, outStr, "exit=1", "direct socket connection should fail in empty net NS")
}

// TestCurb_Proxy_PlainHTTP tests that plain HTTP works through the proxy with --allow-http.
func TestCurb_Proxy_PlainHTTP(t *testing.T) {
	requireProxyNS(t)
	requireExternalHTTP(t)

	// Resolve to host IP to use in the test.
	ip := resolveForTest(t, "example.com")

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--domains", "*", "--allow-http",
		"--", "sh", "-c",
		fmt.Sprintf("curl -sf --connect-timeout 10 http://%s/ -H 'Host: example.com' | head -c 200", ip))
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "plain HTTP through proxy failed: %s", outStr)
	assert.Contains(t, outStr, "Example Domain", "expected example.com HTML content")
}

// TestCurb_Proxy_IPTarget tests CONNECT to an IP address allowed by --ips.
func TestCurb_Proxy_IPTarget(t *testing.T) {
	requireProxyNS(t)
	requireExternalHTTP(t)

	ip := resolveForTest(t, "example.com")

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--ips", ip,
		"--", "sh", "-c",
		fmt.Sprintf("curl -sf --connect-timeout 10 -k https://%s/ -H 'Host: example.com' | head -c 200", ip))
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "IP target through proxy failed: %s", outStr)
	assert.Contains(t, outStr, "Example Domain", "expected example.com HTML content")
}

// TestCurb_Proxy_DryRun verifies that dry-run output mentions proxy.
func TestCurb_Proxy_DryRun(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--dry-run", "--domains", "example.com", "--", "echo")
	out, err := cmd.CombinedOutput()
	outStr := string(out)
	require.NoError(t, err, "dry-run failed: %s", outStr)

	assert.Contains(t, outStr, "proxy:      127.0.0.1:")
	assert.Contains(t, outStr, "socks5 127.0.0.1:")
	assert.Contains(t, outStr, "ca cert:")
	assert.Contains(t, outStr, "example.com")
}

// TestCurb_Proxy_WildcardDomains tests that --domains '*' allows all HTTPS traffic through proxy.
func TestCurb_Proxy_WildcardDomains(t *testing.T) {
	requireProxyNS(t)

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--domains", "*",
		"--", "sh", "-c", "curl -sf --connect-timeout 10 https://example.com/ | head -c 200")
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "wildcard domain curl failed: %s", outStr)
	assert.Contains(t, outStr, "Example Domain")
}

// TestCurb_Proxy_TUN_CurlAllowed tests proxy+TUN with --tun.
func TestCurb_Proxy_TUN_CurlAllowed(t *testing.T) {
	requireNetNS(t)

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--tun", "--domains", "example.com",
		"--", "sh", "-c", "curl -sf --connect-timeout 10 https://example.com/ | head -c 200")
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "proxy+TUN curl to allowed domain failed: %s", outStr)
	assert.Contains(t, outStr, "Example Domain")
}

// TestCurb_Proxy_TUN_DryRun verifies dry-run output with proxy+TUN.
func TestCurb_Proxy_TUN_DryRun(t *testing.T) {
	requireUserNS(t)

	cmd := exec.Command(curbBin, "--dry-run", "--tun", "--domains", "example.com", "--", "echo")
	out, err := cmd.CombinedOutput()
	outStr := string(out)
	require.NoError(t, err, "dry-run failed: %s", outStr)

	assert.Contains(t, outStr, "proxy:")
	assert.Contains(t, outStr, "tun:        on")
}

// TestCurb_Proxy_TUN_Unavailable tests that proxy works even when TUN is unavailable.
func TestCurb_Proxy_TUN_Unavailable(t *testing.T) {
	requireProxyNS(t)
	if testCaps.TUN() == nil {
		t.Skip("TUN is available; this test requires TUN to be unavailable")
	}

	// --tun but TUN is unavailable: should degrade to proxy-only with a warning.
	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--tun", "--domains", "example.com",
		"--", "sh", "-c", "curl -sf --connect-timeout 10 https://example.com/ | head -c 200")
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "proxy should work even with TUN unavailable: %s", outStr)
	assert.Contains(t, outStr, "Example Domain")
}

// TestCurb_Proxy_SOCKS5CurlAllowed tests that curl via SOCKS5 to an allowed domain works.
func TestCurb_Proxy_SOCKS5CurlAllowed(t *testing.T) {
	requireProxyNS(t)

	// curl uses ALL_PROXY=socks5h://... automatically.
	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--domains", "example.com",
		"--", "sh", "-c",
		"curl -sf --connect-timeout 10 --proxy \"$ALL_PROXY\" https://example.com/ | head -c 200")
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "curl via SOCKS5 to allowed domain failed: %s", outStr)
	assert.Contains(t, outStr, "Example Domain")
}

// TestCurb_Proxy_SOCKS5CurlBlocked tests that curl via SOCKS5 to a blocked domain fails.
func TestCurb_Proxy_SOCKS5CurlBlocked(t *testing.T) {
	requireProxyNS(t)

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--domains", "example.com",
		"--", "sh", "-c",
		"curl -sf --connect-timeout 10 --proxy \"$ALL_PROXY\" https://blocked.example.org/ 2>&1; echo exit=$?")
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	_ = err
	assert.Contains(t, outStr, "exit=", "expected curl exit code in output")
	assert.NotContains(t, outStr, "exit=0", "curl via SOCKS5 to blocked domain should fail")
}

// TestCurb_Proxy_SOCKS5EnvVars verifies that SOCKS5-related env vars are set.
func TestCurb_Proxy_SOCKS5EnvVars(t *testing.T) {
	requireProxyNS(t)

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--domains", "example.com",
		"--", "sh", "-c", "echo ALL_PROXY=$ALL_PROXY; echo SOCKS_ADDR=$_CURB_SOCKS_ADDR")
	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "env var check failed: %s", outStr)

	assert.Contains(t, outStr, "ALL_PROXY=socks5h://127.0.0.1:")
	assert.Contains(t, outStr, "SOCKS_ADDR=127.0.0.1:")
}
