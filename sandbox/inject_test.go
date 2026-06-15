package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/upsun/curb/clog"
)

func testLogger(t *testing.T) *clog.Logger {
	t.Helper()
	log, err := clog.New("", false, false, true) // quiet
	require.NoError(t, err)
	return log
}

func TestParseInjectBearer(t *testing.T) {
	specs, err := parseInjectBearer([]string{"api.github.com=@TOKEN", "example.com=literal"})
	require.NoError(t, err)
	require.Len(t, specs, 2)
	assert.Equal(t, "api.github.com", specs[0].host)
	assert.Equal(t, "@TOKEN", specs[0].source)

	for _, bad := range []string{"", "noequals", "=missinghost", "host="} {
		_, err := parseInjectBearer([]string{bad})
		assert.Error(t, err, "expected error for %q", bad)
	}

	// Wildcards must be rejected: "*" would broaden the allowlist to every
	// domain while never matching a binding.
	for _, bad := range []string{"*=@T", "*.example.com=@T"} {
		_, err := parseInjectBearer([]string{bad})
		assert.Error(t, err, "expected wildcard %q to be rejected", bad)
	}

	// Hosts are normalized to lowercase with no trailing dot.
	specs, err = parseInjectBearer([]string{"API.GitHub.COM.=@T"})
	require.NoError(t, err)
	assert.Equal(t, "api.github.com", specs[0].host)
}

func TestParseInjectBearer_FillsAuthorization(t *testing.T) {
	specs, err := parseInjectBearer([]string{"api.github.com=@TOK"})
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "Authorization", specs[0].header)
	assert.Equal(t, "Bearer ", specs[0].prefix)
}

func TestParseInjectHeader(t *testing.T) {
	specs, err := parseInjectHeader([]string{"api.anthropic.com=x-api-key=@ANTHROPIC_API_KEY"})
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "api.anthropic.com", specs[0].host)
	assert.Equal(t, "x-api-key", specs[0].header)
	assert.Equal(t, "", specs[0].prefix)
	assert.Equal(t, "@ANTHROPIC_API_KEY", specs[0].source)

	// A literal value containing '=' is preserved (split is HOST=HEADER=rest).
	specs, err = parseInjectHeader([]string{"h.com=X-Tok=ab=cd"})
	require.NoError(t, err)
	assert.Equal(t, "ab=cd", specs[0].source)

	for _, bad := range []string{
		"", "h.com", "h.com=x-api-key", "=x=y", "h.com==y",
		"h.com=bad header=y", "*=x=@T", "*.h.com=x=@T",
		"h.com=x/y=@T", "h.com=x(y)=@T", "h.com=a:b=@T", // invalid header-name tokens
	} {
		_, err := parseInjectHeader([]string{bad})
		assert.Error(t, err, "expected error for %q", bad)
	}

	// Hosts are normalized to lowercase with no trailing dot.
	specs, err = parseInjectHeader([]string{"API.Anthropic.COM.=x-api-key=@T"})
	require.NoError(t, err)
	assert.Equal(t, "api.anthropic.com", specs[0].host)
}

func TestResolveSecretSource(t *testing.T) {
	log := testLogger(t)

	t.Setenv("CURB_TEST_TOKEN", "s3cret")

	// Required @VAR: value when set; error when unset.
	val, ok, err := resolveSecretSource("@CURB_TEST_TOKEN", log)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "s3cret", val)

	_, _, err = resolveSecretSource("@CURB_TEST_UNSET", log)
	assert.Error(t, err)

	// Optional @?VAR: value when set; skip (ok=false, no error) when unset.
	val, ok, err = resolveSecretSource("@?CURB_TEST_TOKEN", log)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "s3cret", val)

	val, ok, err = resolveSecretSource("@?CURB_TEST_UNSET", log)
	require.NoError(t, err)
	assert.False(t, ok, "optional source skips when unset")
	assert.Empty(t, val)

	// Literal value is returned (with a warning, not asserted here).
	val, ok, err = resolveSecretSource("literal-token", log)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "literal-token", val)
}

func TestWriteCABundle(t *testing.T) {
	dir := t.TempDir()
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nPERRUNCA\n-----END CERTIFICATE-----\n")

	if systemCABundle() == "" {
		// Without system roots, the bundle would override TLS trust with an
		// incomplete set, so injection fails rather than break other hosts.
		_, err := writeCABundle(dir, caPEM)
		require.Error(t, err)
		return
	}

	path, err := writeCABundle(dir, caPEM)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "ca-bundle.pem"), path)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	// The per-run CA is appended after the system roots.
	assert.Contains(t, string(data), "PERRUNCA")
	assert.Greater(t, len(data), len(caPEM), "combined bundle should include system roots")
}
