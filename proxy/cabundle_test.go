package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemCACertPath(t *testing.T) {
	path := SystemCACertPath()
	if path == "" {
		t.Skip("no system CA bundle found on this system")
	}
	_, err := os.Stat(path)
	assert.NoError(t, err)
}

func TestWriteCombinedBundle(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	dir := t.TempDir()
	bundlePath, systemPath, err := WriteCombinedBundle(dir, ca)
	require.NoError(t, err)

	assert.Equal(t, filepath.Join(dir, "ca-certificates.crt"), bundlePath)
	assert.NotEmpty(t, systemPath)

	// Combined bundle should contain both system certs and the ephemeral CA.
	combined, err := os.ReadFile(bundlePath)
	require.NoError(t, err)

	assert.Contains(t, string(combined), string(ca.CertPEM))
	assert.True(t, len(combined) > len(ca.CertPEM), "combined bundle should be larger than just the CA PEM")

	// Should contain at least one system cert (BEGIN CERTIFICATE before our CA).
	parts := strings.SplitN(string(combined), string(ca.CertPEM), 2)
	assert.Contains(t, parts[0], "BEGIN CERTIFICATE")
}
