package netstack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHTTPHost_Standard(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, end, err := parseHTTPHost(data)
	require.NoError(t, err)
	assert.Equal(t, "example.com", host)
	assert.Equal(t, len(data), end)
}

func TestParseHTTPHost_WithPort(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n")
	host, _, err := parseHTTPHost(data)
	require.NoError(t, err)
	assert.Equal(t, "example.com", host)
}

func TestParseHTTPHost_MixedCase(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nhOsT: Example.COM\r\n\r\n")
	host, _, err := parseHTTPHost(data)
	require.NoError(t, err)
	assert.Equal(t, "Example.COM", host)
}

func TestParseHTTPHost_Missing(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n")
	_, _, err := parseHTTPHost(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no Host header")
}

func TestParseHTTPHost_NoHeaderTerminator(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n")
	_, _, err := parseHTTPHost(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no header terminator")
}

func TestParseHTTPHost_MultipleHeaders(t *testing.T) {
	data := []byte("POST /api HTTP/1.1\r\nContent-Type: application/json\r\nHost: api.example.com\r\nAccept: */*\r\n\r\n{}")
	host, end, err := parseHTTPHost(data)
	require.NoError(t, err)
	assert.Equal(t, "api.example.com", host)
	// headerEnd should point past the \r\n\r\n, before the body.
	assert.Less(t, end, len(data))
}

func TestParseHTTPHost_WhitespaceInValue(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost:   example.com  \r\n\r\n")
	host, _, err := parseHTTPHost(data)
	require.NoError(t, err)
	assert.Equal(t, "example.com", host)
}
