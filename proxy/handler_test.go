package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectThroughProxy sends a CONNECT request to the proxy for the given
// target and returns a buffered reader over the tunneled connection.
// It asserts the CONNECT response is 200 OK.
func connectThroughProxy(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "CONNECT should succeed")
	return conn, br
}

func setupProxy(t *testing.T) *httptest.Server {
	t.Helper()
	h := &Handler{
		FilterBase: FilterBase{
			DomainCheck: func(d string) bool { return d == "allowed.example.com" },
			IPCheck:     func(a netip.Addr) bool { return a == netip.MustParseAddr("93.184.215.14") },
		},
	}
	proxyServer := httptest.NewServer(h)
	t.Cleanup(proxyServer.Close)
	return proxyServer
}

func TestHandler_CONNECT_Allowed(t *testing.T) {
	// Start an HTTP upstream that the proxy will tunnel to.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello from upstream"))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamAddr := upstreamURL.Host // 127.0.0.1:<port>

	h := &Handler{
		FilterBase: FilterBase{
			IPCheck: func(a netip.Addr) bool { return a.IsLoopback() },
		},
	}
	proxyServer := httptest.NewServer(h)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)

	// CONNECT to the upstream's address. The proxy checks the IP, dials,
	// and tunnels the connection.
	conn, br := connectThroughProxy(t, proxyURL.Host, upstreamAddr)
	defer func() { _ = conn.Close() }()

	// Send an HTTP request through the tunnel and verify the response.
	_, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)

	tunnelResp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer func() { _ = tunnelResp.Body.Close() }()
	body, _ := io.ReadAll(tunnelResp.Body)
	assert.Equal(t, "hello from upstream", string(body))
}

func TestHandler_CONNECT_Blocked(t *testing.T) {
	proxyServer := setupProxy(t)

	proxyURL, _ := url.Parse(proxyServer.URL)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{Transport: transport}

	_, err := client.Get("https://blocked.example.com/")
	require.Error(t, err)
	// Should get Forbidden from the proxy.
	assert.Contains(t, err.Error(), "Forbidden")
}

func TestHandler_CONNECT_IPAllowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ip ok"))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamAddr := upstreamURL.Host // 127.0.0.1:<port>

	h := &Handler{
		FilterBase: FilterBase{
			IPCheck: func(a netip.Addr) bool { return a.IsLoopback() },
		},
	}
	proxyServer := httptest.NewServer(h)
	defer proxyServer.Close()
	proxyURL, _ := url.Parse(proxyServer.URL)

	conn, br := connectThroughProxy(t, proxyURL.Host, upstreamAddr)
	defer func() { _ = conn.Close() }()

	_, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)

	tunnelResp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer func() { _ = tunnelResp.Body.Close() }()
	body, _ := io.ReadAll(tunnelResp.Body)
	assert.Equal(t, "ip ok", string(body))
}

func TestHandler_CONNECT_IPBlocked(t *testing.T) {
	proxyServer := setupProxy(t)

	proxyURL, _ := url.Parse(proxyServer.URL)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{Transport: transport}

	_, err := client.Get("https://10.0.0.1:443/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Forbidden")
}

func TestHandler_HTTP_Allowed(t *testing.T) {
	// Start an HTTP upstream.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("http ok"))
	}))
	defer upstream.Close()

	// Parse upstream host:port.
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamHost := upstreamURL.Host

	h := &Handler{
		FilterBase: FilterBase{
			DomainCheck: func(d string) bool { return true },
			IPCheck:     func(a netip.Addr) bool { return true },
		},
	}
	proxyServer := httptest.NewServer(h)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("http://" + upstreamHost + "/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "http ok", string(body))
}

func TestConnListener(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	cl := NewConnListener(addr)

	// Enqueue a connection.
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	require.NoError(t, cl.Enqueue(server))

	// Accept should return it.
	got, err := cl.Accept()
	require.NoError(t, err)
	assert.Equal(t, server, got)

	// Close should make Accept return error.
	require.NoError(t, cl.Close())
	_, err = cl.Accept()
	assert.Error(t, err)

	// Enqueue after Close should return error.
	s2, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	defer func() { _ = s2.Close() }()
	assert.Error(t, cl.Enqueue(s2), "Enqueue after Close should fail")
}
