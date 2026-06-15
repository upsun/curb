package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authRecorder is an upstream TLS server that records the headers of each
// request it receives.
type authRecorder struct {
	srv     *httptest.Server
	headers []http.Header
}

func newAuthRecorder(t *testing.T) *authRecorder {
	t.Helper()
	rec := &authRecorder{}
	rec.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.headers = append(rec.headers, r.Header.Clone())
		_, _ = io.WriteString(w, "ok")
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

// injectTestProxy starts a curb proxy that allows the given hosts and injects
// the configured bearer tokens, routing upstream to the local recorders.
func injectTestProxy(t *testing.T, ca *CA, bindings map[string]string, upstreams map[string]*authRecorder) *url.URL {
	t.Helper()
	binds := make(map[string][]Injection, len(bindings))
	for host, token := range bindings {
		binds[host] = []Injection{{Header: "Authorization", Value: "Bearer " + token}}
	}
	return injectTestProxyWith(t, ca, binds, upstreams)
}

// injectTestProxyWith starts a curb proxy with arbitrary header injections.
func injectTestProxyWith(t *testing.T, ca *CA, bindings map[string][]Injection, upstreams map[string]*authRecorder) *url.URL {
	t.Helper()

	allowed := map[string]bool{}
	dialMap := map[string]*authRecorder{}
	for host, rec := range upstreams {
		allowed[host] = true
		dialMap[net.JoinHostPort(host, "443")] = rec
	}

	injector := NewInjector(ca)
	for host, injs := range bindings {
		for _, inj := range injs {
			injector.Bind(host, inj)
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

	handler := &Handler{
		FilterBase: FilterBase{DomainCheck: func(h string) bool { return allowed[h] }},
		Injector:   injector,
	}
	proxySrv := httptest.NewServer(handler)
	t.Cleanup(proxySrv.Close)

	u, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)
	return u
}

// clientThroughProxy builds an HTTP client that routes through the curb proxy
// and trusts the per-run CA for the terminated TLS.
func clientThroughProxy(proxyURL *url.URL, ca *CA) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

func get(t *testing.T, client *http.Client, rawURL string) string {
	t.Helper()
	resp, err := client.Get(rawURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// TestInjector_BindingNormalizesHost confirms bindings match CONNECT targets
// regardless of case or a trailing dot.
func TestInjector_BindingNormalizesHost(t *testing.T) {
	in := &Injector{byHost: map[string][]Injection{}}
	in.Bind("API.GitHub.COM.", Injection{Header: "Authorization", Value: "Bearer t"})

	for _, host := range []string{"api.github.com", "API.GITHUB.COM", "api.github.com.", "Api.GitHub.Com."} {
		injs, ok := in.binding(host)
		require.True(t, ok, "expected binding to match %q", host)
		assert.Equal(t, "Bearer t", injs[0].Value)
	}

	_, ok := in.binding("other.com")
	assert.False(t, ok)
}

// TestInjector_InjectsBoundCredential verifies the placeholder request leaves
// the sandbox with the real credential attached.
func TestInjector_InjectsBoundCredential(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	gh := newAuthRecorder(t)
	proxyURL := injectTestProxy(t, ca,
		map[string]string{"api.github.com": "ghs_realtoken"},
		map[string]*authRecorder{"api.github.com": gh},
	)
	client := clientThroughProxy(proxyURL, ca)

	body := get(t, client, "https://api.github.com/user")
	assert.Equal(t, "ok", body)
	require.Equal(t, 1, gh.count())
	assert.Equal(t, "Bearer ghs_realtoken", gh.got("Authorization")[0])
}

// TestInjector_BindsCredentialToDestination is the central correctness
// property: a credential is attached only to the host it was provisioned for,
// never stapled to another host the agent names.
func TestInjector_BindsCredentialToDestination(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	gh := newAuthRecorder(t)
	other := newAuthRecorder(t)
	proxyURL := injectTestProxy(t, ca,
		map[string]string{
			"api.github.com":  "ghs_realtoken",
			"api.example.com": "example_token",
		},
		map[string]*authRecorder{
			"api.github.com":  gh,
			"api.example.com": other,
		},
	)
	client := clientThroughProxy(proxyURL, ca)

	get(t, client, "https://api.github.com/user")
	get(t, client, "https://api.example.com/data")

	require.Equal(t, 1, gh.count())
	require.Equal(t, 1, other.count())
	// Each host sees only its own credential.
	assert.Equal(t, "Bearer ghs_realtoken", gh.got("Authorization")[0])
	assert.Equal(t, "Bearer example_token", other.got("Authorization")[0])
	assert.NotContains(t, gh.got("Authorization")[0], "example_token")
	assert.NotContains(t, other.got("Authorization")[0], "ghs_realtoken")
}

// TestInjector_PlaceholderIsOverwritten confirms a placeholder the sandbox
// might send is replaced, not honored.
func TestInjector_PlaceholderIsOverwritten(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	gh := newAuthRecorder(t)
	proxyURL := injectTestProxy(t, ca,
		map[string]string{"api.github.com": "ghs_realtoken"},
		map[string]*authRecorder{"api.github.com": gh},
	)
	client := clientThroughProxy(proxyURL, ca)

	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/user", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer gh_placeholder")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, 1, gh.count())
	assert.Equal(t, "Bearer ghs_realtoken", gh.got("Authorization")[0])
}

// TestInjector_InjectsArbitraryHeader covers --inject-header: a non-bearer
// header (e.g. x-api-key, as Anthropic uses) is set on the outbound request.
func TestInjector_InjectsArbitraryHeader(t *testing.T) {
	ca, err := NewCA()
	require.NoError(t, err)

	up := newAuthRecorder(t)
	proxyURL := injectTestProxyWith(t, ca,
		map[string][]Injection{
			"api.anthropic.com": {{Header: "x-api-key", Value: "sk-ant-real"}},
		},
		map[string]*authRecorder{"api.anthropic.com": up},
	)
	client := clientThroughProxy(proxyURL, ca)

	req, err := http.NewRequest(http.MethodGet, "https://api.anthropic.com/v1/models", nil)
	require.NoError(t, err)
	req.Header.Set("x-api-key", "sk-ant-placeholder") // overwritten, not honored
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, 1, up.count())
	assert.Equal(t, "sk-ant-real", up.got("x-api-key")[0])
	// The bearer header is not added for a header-only binding.
	assert.Empty(t, up.got("Authorization")[0])
}
