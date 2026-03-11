package netstack

import (
	"net"
	"testing"
	"time"

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

func TestParseHTTPHost_DoubleHost(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: first.com\r\nHost: second.com\r\n\r\n")
	host, _, err := parseHTTPHost(data)
	require.NoError(t, err)
	assert.Equal(t, "first.com", host, "first Host header should be returned")
}

func TestHandleHTTPConnection_BlockedDomain(t *testing.T) {
	client, server := net.Pipe()
	filter := &FilterConfig{
		Check:     func(string) bool { return false },
		AllowHTTP: true,
	}

	done := make(chan struct{})
	go func() {
		handleHTTPConnection(server, "93.184.216.34:80", filter)
		close(done)
	}()

	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: blocked.com\r\n\r\n"))
	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	assert.Contains(t, string(buf[:n]), "403 Forbidden")
	_ = client.Close()
	<-done
}

func TestHandleHTTPConnection_MissingHost(t *testing.T) {
	client, server := net.Pipe()
	filter := &FilterConfig{
		Check:     func(string) bool { return true },
		AllowHTTP: true,
	}

	done := make(chan struct{})
	go func() {
		handleHTTPConnection(server, "93.184.216.34:80", filter)
		close(done)
	}()

	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"))
	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	assert.Contains(t, string(buf[:n]), "403 Forbidden")
	_ = client.Close()
	<-done
}

func TestHandleHTTPConnection_AllowedDomain(t *testing.T) {
	client, server := net.Pipe()
	filter := &FilterConfig{
		Check:     func(string) bool { return true },
		AllowHTTP: true,
	}

	done := make(chan struct{})
	go func() {
		// Dial will fail (no real server), but the handler should NOT send 403.
		handleHTTPConnection(server, "127.0.0.1:1", filter)
		close(done)
	}()

	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: allowed.com\r\n\r\n"))
	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	if n > 0 {
		assert.NotContains(t, string(buf[:n]), "403 Forbidden", "allowed domain should not get 403")
	}
	_ = client.Close()
	<-done
}

func TestHandleHTTPConnection_MixedCaseHost(t *testing.T) {
	client, server := net.Pipe()
	var checkedDomain string
	filter := &FilterConfig{
		Check: func(domain string) bool {
			checkedDomain = domain
			return true
		},
		AllowHTTP: true,
	}

	done := make(chan struct{})
	go func() {
		handleHTTPConnection(server, "127.0.0.1:1", filter)
		close(done)
	}()

	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: EXAMPLE.COM\r\n\r\n"))
	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := client.Read(buf)
	if n > 0 {
		assert.NotContains(t, string(buf[:n]), "403 Forbidden")
	}
	assert.Equal(t, "EXAMPLE.COM", checkedDomain, "Check receives the original case from the Host header")
	_ = client.Close()
	<-done
}
