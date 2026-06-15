package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseInjectHeader(t *testing.T) {
	specs, err := parseInjectHeader([]string{"ANTHROPIC_API_KEY=api.anthropic.com"})
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "ANTHROPIC_API_KEY", specs[0].envVar)
	assert.Equal(t, "api.anthropic.com", specs[0].host)

	for _, bad := range []string{
		"", "ANTHROPIC_API_KEY", "=h.com", "TOK=", // missing var or host
		"1BAD=h.com",          // invalid env var name (leading digit)
		"bad-var=h.com",       // invalid env var name (dash)
		"T=*", "T=*.h.com",    // wildcard hosts rejected
		"TOK=not a host",      // invalid host
	} {
		_, err := parseInjectHeader([]string{bad})
		assert.Error(t, err, "expected error for %q", bad)
	}

	// Hosts are normalized to lowercase with no trailing dot.
	specs, err = parseInjectHeader([]string{"T=API.Anthropic.COM."})
	require.NoError(t, err)
	assert.Equal(t, "api.anthropic.com", specs[0].host)
}

func TestInjectPlaceholder(t *testing.T) {
	// Stable per env var, and distinct vars get distinct placeholders.
	assert.Equal(t, injectPlaceholder("ANTHROPIC_API_KEY"), injectPlaceholder("ANTHROPIC_API_KEY"))
	assert.NotEqual(t, injectPlaceholder("A"), injectPlaceholder("B"))
	assert.Contains(t, injectPlaceholder("GH_TOKEN"), "GH_TOKEN")
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
