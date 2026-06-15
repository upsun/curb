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
	hosts   []string
}

func newAuthRecorder(t *testing.T) *authRecorder {
	t.Helper()
	rec := &authRecorder{}
	rec.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.headers = append(rec.headers, r.Header.Clone())
		rec.hosts = append(rec.hosts, r.Host)
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

// injectTestProxy starts a curb proxy that allows the given hosts and applies
// the configured placeholder substitutions, routing upstream to the local
// recorders.
func injectTestProxy(t *testing.T, ca *CA, bindings map[string][]Injection, upstreams map[string]*authRecorder) *url.URL {
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

// getWithHeader issues a GET through the proxy with one header set, returning
// the upstream's response body.
func getWithHeader(t *testing.T, client *http.Client, rawURL, name, value string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	req.Header.Set(name, value)
	resp, err := client.Do(req)
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
	in.Bind("API.GitHub.COM.", Injection{Placeholder: "PH", Value: "real"})

	for _, host := range []string{"api.github.com", "API.GITHUB.COM", "api.github.com.", "Api.GitHub.Com."} {
		injs, ok := in.binding(host)
		require.True(t, ok, "expected binding to match %q", host)
		assert.Equal(t, "real", injs[0].Value)
	}

	_, ok := in.binding("other.com")
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
	client := clientThroughProxy(proxyURL, ca)

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
	client := clientThroughProxy(proxyURL, ca)

	body := getWithHeader(t, client, "https://api.github.com/user", "Authorization", "Bearer GH_PH")
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
		client := clientThroughProxy(proxyURL, ca)

		getWithHeader(t, client, "https://api.anthropic.com/v1/models", tc.header, tc.value)
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
	client := clientThroughProxy(proxyURL, ca)

	// Send github's placeholder to both hosts: only github substitutes it.
	getWithHeader(t, client, "https://api.github.com/user", "Authorization", "Bearer GH_PH")
	getWithHeader(t, client, "https://api.example.com/data", "Authorization", "Bearer GH_PH")

	require.Equal(t, 1, gh.count())
	require.Equal(t, 1, other.count())
	assert.Equal(t, "Bearer ghs_realtoken", gh.got("Authorization")[0])
	// example.com has no binding for github's placeholder, so it passes through
	// unsubstituted — github's real token never reaches another host.
	assert.Equal(t, "Bearer GH_PH", other.got("Authorization")[0])
	assert.NotContains(t, other.got("Authorization")[0], "ghs_realtoken")
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
	client := clientThroughProxy(proxyURL, ca)

	// No placeholder present: nothing is substituted, and the value is intact.
	getWithHeader(t, client, "https://api.github.com/user", "X-Custom", "untouched-value")
	require.Equal(t, 1, gh.count())
	assert.Equal(t, "untouched-value", gh.got("X-Custom")[0])
	assert.Empty(t, gh.got("Authorization")[0])
}
