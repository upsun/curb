package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authRecorder is an upstream TLS server that records the headers of each
// request it receives.
type authRecorder struct {
	srv     *httptest.Server
	headers []http.Header
	hosts   []string
}

func newAuthRecorder(t *testing.T) *authRecorder {
	t.Helper()
	return newAuthRecorderWith(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
}

// newAuthRecorderWith starts a recording TLS upstream with a custom handler;
// each request is recorded before the handler runs.
func newAuthRecorderWith(t *testing.T, handler http.HandlerFunc) *authRecorder {
	t.Helper()
	rec := &authRecorder{}
	rec.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.headers = append(rec.headers, r.Header.Clone())
		rec.hosts = append(rec.hosts, r.Host)
		handler(w, r)
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

// count returns how many requests the upstream received.
func (r *authRecorder) count() int { return len(r.headers) }

// got returns the named header's value from each received request, in order.
func (r *authRecorder) got(name string) []string {
	out := make([]string, 0, len(r.headers))
	for _, h := range r.headers {
		out = append(out, h.Get(name))
	}
	return out
}

// newTestInjector builds an injector for the given bindings whose upstream
// reaches the local recorders instead of the real hosts, plus the set of
// allowed hosts derived from the upstreams.
func newTestInjector(ca *CA, bindings map[string][]Injection, upstreams map[string]*authRecorder) (*Injector, map[string]bool) {
	allowed := map[string]bool{}
	dialMap := map[string]*authRecorder{}
	for host, rec := range upstreams {
		allowed[host] = true
		dialMap[net.JoinHostPort(host, "443")] = rec
	}

	injector := NewInjector(ca)
	for host, injs := range bindings {
		for _, inj := range injs {
			injector.Bind(host, "443", inj)
		}
	}
	// Reach the local recorders instead of the real hosts, trusting each
	// server's own cert (httptest's built-in cert is issued for example.com).
	injector.Upstream = &http.Transport{
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			rec, ok := dialMap[addr]
			if !ok {
				return nil, fmt.Errorf("unexpected upstream %s", addr)
			}
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", rec.srv.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			pool.AddCert(rec.srv.Certificate())
			tc := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12})
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	return injector, allowed
}

// injectTestProxy starts a curb proxy that allows the given hosts and applies
// the configured placeholder substitutions, routing upstream to the local
// recorders.
func injectTestProxy(t *testing.T, ca *CA, bindings map[string][]Injection, upstreams map[string]*authRecorder) *url.URL {
	t.Helper()

	injector, allowed := newTestInjector(ca, bindings, upstreams)
	handler := &Handler{
		DomainCheck: func(h string) bool { return allowed[h] },
		Injector:    injector,
	}
	proxySrv := httptest.NewServer(handler)
	t.Cleanup(proxySrv.Close)

	u, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)
	return u
}

// clientThroughProxy builds an HTTP client that routes through the curb proxy
// and trusts the per-run CA for the terminated TLS. Idle connections are closed
// on cleanup so hijacked CONNECT tunnels (and their per-connection injection
// servers) do not linger across tests.
func clientThroughProxy(t *testing.T, proxyURL *url.URL, ca *CA) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

// get issues a GET through the proxy, optionally setting one header (given as
// a name, value pair), and returns the upstream's response body.
func get(t *testing.T, client *http.Client, rawURL string, header ...string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	if len(header) > 0 {
		require.Len(t, header, 2, "header must be a name, value pair")
		req.Header.Set(header[0], header[1])
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func TestCA_CertificatesSupportLongSessions(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	now := time.Now()
	assert.Greater(t, ca.cert.NotAfter.Sub(now), 7*24*time.Hour)

	leaf, err := ca.leafFor("api.github.com")
	require.NoError(t, err)
	require.NotNil(t, leaf.Leaf)
	assert.Greater(t, leaf.Leaf.NotAfter.Sub(now), 7*24*time.Hour)
	assert.False(t, leaf.Leaf.NotAfter.After(ca.cert.NotAfter), "leaf must not outlive the CA")

	// Serials are random, not time-derived: two leaves must not collide.
	other, err := ca.leafFor("api.example.com")
	require.NoError(t, err)
	assert.NotEqual(t, leaf.Leaf.SerialNumber, other.Leaf.SerialNumber)
}

// TestInjector_BindingNormalizesHost confirms bindings match CONNECT targets
// regardless of case or a trailing dot, and only on the bound port.
func TestInjector_BindingNormalizesHost(t *testing.T) {
	in := NewInjector(nil)
	in.Bind("API.GitHub.COM.", "443", Injection{Placeholder: "PH", Value: "real"})

	for _, host := range []string{"api.github.com", "API.GITHUB.COM", "api.github.com.", "Api.GitHub.Com."} {
		injs, ok := in.binding(host, "443")
		require.True(t, ok, "expected binding to match %q", host)
		assert.Equal(t, "real", injs[0].Value)
	}

	// A credential bound to :443 must not match a different port.
	_, ok := in.binding("api.github.com", "8443")
	assert.False(t, ok, "binding must not match a non-bound port")

	_, ok = in.binding("other.com", "443")
	assert.False(t, ok)
}

// TestInjector_SetsHostHeader confirms the upstream request's Host header is
// the bound host, not whatever the client put on the decrypted request.
func TestInjector_SetsHostHeader(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	gh := newAuthRecorder(t)
	proxyURL := injectTestProxy(t, ca,
		map[string][]Injection{"api.github.com": {{Placeholder: "GH_PH", Value: "ghs_realtoken"}}},
		map[string]*authRecorder{"api.github.com": gh},
	)
	client := clientThroughProxy(t, proxyURL, ca)

	get(t, client, "https://api.github.com/user")
	require.Equal(t, 1, len(gh.hosts))
	assert.Equal(t, "api.github.com", gh.hosts[0])
}

// TestInjector_ReplacesPlaceholder verifies the placeholder the sandbox sends is
// replaced with the real credential, wherever the client placed it.
func TestInjector_ReplacesPlaceholder(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	gh := newAuthRecorder(t)
	proxyURL := injectTestProxy(t, ca,
		map[string][]Injection{"api.github.com": {{Placeholder: "GH_PH", Value: "ghs_realtoken"}}},
		map[string]*authRecorder{"api.github.com": gh},
	)
	client := clientThroughProxy(t, proxyURL, ca)

	body := get(t, client, "https://api.github.com/user", "Authorization", "Bearer GH_PH")
	assert.Equal(t, "ok", body)
	require.Equal(t, 1, gh.count())
	assert.Equal(t, "Bearer ghs_realtoken", gh.got("Authorization")[0])
}

// TestInjector_HeaderAgnostic is the headline property: one binding works
// whatever header the client carries the placeholder in — no auth-scheme
// knowledge is configured.
func TestInjector_HeaderAgnostic(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	for _, tc := range []struct{ header, value, want string }{
		{"Authorization", "Bearer ANT_PH", "Bearer sk-ant-real"},
		{"x-api-key", "ANT_PH", "sk-ant-real"},
	} {
		up := newAuthRecorder(t)
		proxyURL := injectTestProxy(t, ca,
			map[string][]Injection{"api.anthropic.com": {{Placeholder: "ANT_PH", Value: "sk-ant-real"}}},
			map[string]*authRecorder{"api.anthropic.com": up},
		)
		client := clientThroughProxy(t, proxyURL, ca)

		get(t, client, "https://api.anthropic.com/v1/models", tc.header, tc.value)
		require.Equal(t, 1, up.count())
		assert.Equal(t, tc.want, up.got(tc.header)[0], "header %s", tc.header)
	}
}

// TestInjector_BindsCredentialToDestination is the central correctness
// property: a placeholder is substituted only at the host it was provisioned
// for. A placeholder for one host is not substituted when sent to another.
func TestInjector_BindsCredentialToDestination(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	gh := newAuthRecorder(t)
	other := newAuthRecorder(t)
	proxyURL := injectTestProxy(t, ca,
		map[string][]Injection{
			"api.github.com":  {{Placeholder: "GH_PH", Value: "ghs_realtoken"}},
			"api.example.com": {{Placeholder: "EX_PH", Value: "example_token"}},
		},
		map[string]*authRecorder{
			"api.github.com":  gh,
			"api.example.com": other,
		},
	)
	client := clientThroughProxy(t, proxyURL, ca)

	// Send github's placeholder to both hosts: only github substitutes it.
	get(t, client, "https://api.github.com/user", "Authorization", "Bearer GH_PH")
	get(t, client, "https://api.example.com/data", "Authorization", "Bearer GH_PH")

	require.Equal(t, 1, gh.count())
	require.Equal(t, 1, other.count())
	assert.Equal(t, "Bearer ghs_realtoken", gh.got("Authorization")[0])
	// example.com has no binding for github's placeholder, so it passes through
	// unsubstituted — github's real token never reaches another host.
	assert.Equal(t, "Bearer GH_PH", other.got("Authorization")[0])
	assert.NotContains(t, other.got("Authorization")[0], "ghs_realtoken")
}

// TestInjector_RefusesPlainHTTP confirms a bound host:port reached over plain
// HTTP is refused, not forwarded: the credential must never go out over
// cleartext. The refusal is port-exact — plain HTTP to the same host on a port
// without a binding is relayed unchanged, per the documented contract.
func TestInjector_RefusesPlainHTTP(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	// A loopback port with nothing listening: the unbound-port request should
	// get a dial failure, not the injection refusal.
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	require.NoError(t, closedLn.Close())

	injector := NewInjector(ca)
	injector.Bind("localhost", strconv.Itoa(closedPort), Injection{Placeholder: "PH", Value: "real"})
	handler := &Handler{
		DomainCheck: func(h string) bool { return h == "localhost" },
		Injector:    injector,
	}
	proxySrv := httptest.NewServer(handler)
	t.Cleanup(proxySrv.Close)
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Plain HTTP to the bound host:port is refused before dialing.
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/user", closedPort))
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	// The refusal names the exact bound destination: bindings are host:port.
	assert.Contains(t, string(body), fmt.Sprintf("requires HTTPS for localhost:%d", closedPort))

	// Plain HTTP to the same host on an unbound port is relayed (and fails only
	// at dial time, since nothing is listening).
	resp, err = client.Get(fmt.Sprintf("http://localhost:%d/user", closedPort+1))
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.NotContains(t, string(body), "requires HTTPS")
}

// TestSOCKS5Server_Injects confirms the SOCKS5 egress path injects credentials
// for a bound host, matching the HTTP CONNECT path. A socks5h client sends the
// hostname, so the binding matches and TLS is terminated.
func TestSOCKS5Server_Injects(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	gh := newAuthRecorder(t)
	injector, allowed := newTestInjector(ca,
		map[string][]Injection{"api.github.com": {{Placeholder: "GH_PH", Value: "ghs_realtoken"}}},
		map[string]*authRecorder{"api.github.com": gh},
	)
	srv := &SOCKS5Server{
		DomainCheck: func(h string) bool { return allowed[h] },
		Injector:    injector,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.Serve(ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// SOCKS5 no-auth handshake.
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, []byte{0x05, 0x00}, reply)

	// CONNECT api.github.com:443 by name (socks5h).
	host := "api.github.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(443>>8), byte(443&0xff))
	_, err = conn.Write(req)
	require.NoError(t, err)
	repHeader := make([]byte, 10)
	_, err = io.ReadFull(conn, repHeader)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), repHeader[1], "expected success reply")

	// The proxy now terminates TLS with the per-run CA; send a request carrying
	// the placeholder and confirm the upstream sees the real credential.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	tc := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())

	httpReq, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	require.NoError(t, err)
	httpReq.Header.Set("Authorization", "Bearer GH_PH")
	require.NoError(t, httpReq.Write(tc))

	resp, err := http.ReadResponse(bufio.NewReader(tc), httpReq)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.Equal(t, 1, gh.count())
	assert.Equal(t, "Bearer ghs_realtoken", gh.got("Authorization")[0])
}

// dialInjectTLS dials the proxy, issues a CONNECT for host:443, and completes
// a TLS handshake trusted via the per-run CA. It returns the decrypted stream
// and a reader for responses on it.
func dialInjectTLS(t *testing.T, proxyURL *url.URL, ca *CA, host string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	raw, err := net.Dial("tcp", proxyURL.Host)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = fmt.Fprintf(raw, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	tc := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	return tc, bufio.NewReader(tc)
}

// TestInjector_UpgradeWebSocket confirms an HTTP/1.1 Upgrade flow (WebSocket
// handshake and bidirectional stream) works on a bound host, with the
// credential injected into the handshake request.
func TestInjector_UpgradeWebSocket(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	rec := newAuthRecorderWith(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "expected upgrade", http.StatusBadRequest)
			return
		}
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		line, err := brw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = brw.WriteString("echo:" + line)
		_ = brw.Flush()
	})

	proxyURL := injectTestProxy(t, ca,
		map[string][]Injection{"api.example.com": {{Placeholder: "EX_PH", Value: "real_token"}}},
		map[string]*authRecorder{"api.example.com": rec},
	)
	tc, br := dialInjectTLS(t, proxyURL, ca, "api.example.com")

	_, err = fmt.Fprintf(tc, "GET /ws HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nAuthorization: Bearer EX_PH\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	_, err = io.WriteString(tc, "hello\n")
	require.NoError(t, err)
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "echo:hello\n", line)

	require.Equal(t, 1, rec.count())
	assert.Equal(t, "Bearer real_token", rec.got("Authorization")[0])
}

// TestInjector_KeepAliveAfterUnreadBody confirms the connection stays usable
// when the upstream responds without consuming the request body: the next
// request on the same connection must not be corrupted by leftover body bytes.
func TestInjector_KeepAliveAfterUnreadBody(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	rec := newAuthRecorderWith(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Reply without reading the body.
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})

	proxyURL := injectTestProxy(t, ca,
		map[string][]Injection{"api.example.com": {{Placeholder: "EX_PH", Value: "real_token"}}},
		map[string]*authRecorder{"api.example.com": rec},
	)
	tc, br := dialInjectTLS(t, proxyURL, ca, "api.example.com")

	body := strings.Repeat("x", 128<<10)
	_, err = fmt.Fprintf(tc, "POST /upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	require.NoError(t, err)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)

	_, err = io.WriteString(tc, "GET /after HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer EX_PH\r\n\r\n")
	require.NoError(t, err)
	resp, err = http.ReadResponse(br, nil)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.Equal(t, 2, rec.count())
	assert.Equal(t, "Bearer real_token", rec.got("Authorization")[1])
}

// TestInjector_ExpectContinue confirms a client using Expect: 100-continue
// receives an interim 100 response instead of stalling until timeout. The
// upstream reads the full body before replying, so the body must cross the
// wire — which cannot happen until the proxy sends the client its 100, making
// the interim response deterministic rather than racing the final one.
func TestInjector_ExpectContinue(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	rec := newAuthRecorderWith(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body) // echo, so the test confirms the body arrived
	})

	proxyURL := injectTestProxy(t, ca,
		map[string][]Injection{"api.example.com": {{Placeholder: "EX_PH", Value: "real_token"}}},
		map[string]*authRecorder{"api.example.com": rec},
	)
	tc, br := dialInjectTLS(t, proxyURL, ca, "api.example.com")

	// Send headers only; withhold the body until an interim 100 arrives.
	_, err = io.WriteString(tc, "POST /upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
	require.NoError(t, err)

	// Read like a real client: consume interim 1xx responses, send the body on
	// the first 100, and stop at the final response. Tolerates more than one
	// interim response but requires that a 100 preceded the body.
	require.NoError(t, tc.SetReadDeadline(time.Now().Add(5*time.Second)))
	var saw100 bool
	for {
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
		require.NoError(t, err, "expected an interim 100 Continue before the final response")
		if resp.StatusCode == http.StatusContinue {
			if !saw100 {
				saw100 = true
				_, err = io.WriteString(tc, "hello")
				require.NoError(t, err)
			}
			continue
		}
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "hello", string(body), "body should reach the upstream after 100")
		break
	}
	require.True(t, saw100, "client should receive an interim 100 Continue")
}

// TestInjector_LeavesOtherHeadersUntouched confirms only the placeholder is
// replaced; unrelated header content passes through verbatim.
func TestInjector_LeavesOtherHeadersUntouched(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	gh := newAuthRecorder(t)
	proxyURL := injectTestProxy(t, ca,
		map[string][]Injection{"api.github.com": {{Placeholder: "GH_PH", Value: "ghs_realtoken"}}},
		map[string]*authRecorder{"api.github.com": gh},
	)
	client := clientThroughProxy(t, proxyURL, ca)

	// No placeholder present: nothing is substituted, and the value is intact.
	get(t, client, "https://api.github.com/user", "X-Custom", "untouched-value")
	require.Equal(t, 1, gh.count())
	assert.Equal(t, "untouched-value", gh.got("X-Custom")[0])
	assert.Empty(t, gh.got("Authorization")[0])
}
