//go:build linux

package sandbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upstreamTLS generates a CA and a leaf certificate valid for dnsNames and
// 127.0.0.1, returning the server cert and the CA in PEM (to trust the server).
func upstreamTLS(t *testing.T, dnsNames []string) (tls.Certificate, []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test upstream CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	cert := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return cert, caPEM
}

// headerRecorder is an HTTPS upstream that records the headers of each request.
type headerRecorder struct {
	mu      sync.Mutex
	headers []http.Header
}

func (r *headerRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.headers = append(r.headers, req.Header.Clone())
		r.mu.Unlock()
		_, _ = fmt.Fprint(w, "ok")
	})
}

// got returns the named header's value from each received request, in order.
func (r *headerRecorder) got(name string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.headers))
	for _, h := range r.headers {
		out = append(out, h.Get(name))
	}
	return out
}

// startTLSServer serves h over TLS on a loopback port and returns the port.
func startTLSServer(t *testing.T, cert tls.Certificate, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{
		Handler:   h,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return port
}

// envWithout returns os.Environ() with the named keys removed, so the test can
// set them unambiguously (Go reads the first match for a key).
func envWithout(keys ...string) []string {
	var out []string
	for _, e := range os.Environ() {
		drop := false
		for _, k := range keys {
			if strings.HasPrefix(e, k+"=") {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, e)
		}
	}
	return out
}

// TestCurb_Inject_EndToEnd runs the real curb binary with --inject-header and a
// sandboxed curl against a local HTTPS server. The sandbox sees only a
// placeholder in the carrier env var; the proxy replaces it with the real
// credential on the wire. It also confirms the real secret never enters the
// sandbox.
func TestCurb_Inject_EndToEnd(t *testing.T) {
	requireProxyNS(t)

	rec := &headerRecorder{}
	cert, caPEM := upstreamTLS(t, []string{"localhost"})
	port := startTLSServer(t, cert, rec.handler())

	// The curb proxy verifies the upstream against system roots; point its
	// process at a trust file containing only this test server's CA.
	caFile := filepath.Join(t.TempDir(), "upstream-ca.pem")
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o644))

	url := fmt.Sprintf("https://localhost:%s/", port)
	// $DEMO_TOKEN inside the sandbox is the placeholder. The script sends it in
	// the Authorization header; the proxy substitutes the real value. Echoing it
	// lets us confirm the sandbox never holds the real secret.
	script := fmt.Sprintf(
		"echo \" seal=$DEMO_TOKEN\"; "+
			"curl -sf --connect-timeout 10 -H \"Authorization: Bearer $DEMO_TOKEN\" %s; echo \" a=$?\"",
		url)

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--host-loopback",
		"--inject-header", "DEMO_TOKEN=localhost",
		"--", "sh", "-c", script)
	cmd.Env = append(envWithout("DEMO_TOKEN", "SSL_CERT_FILE"),
		"DEMO_TOKEN=integration-secret",
		"SSL_CERT_FILE="+caFile,
	)

	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "sandboxed curl failed: %s", outStr)
	assert.Contains(t, outStr, "a=0", "request should succeed (sandbox trusts the per-run CA)")
	assert.Contains(t, outStr, "seal=curb-sealed-placeholder-DEMO_TOKEN", "sandbox sees only the placeholder")
	assert.NotContains(t, outStr, "integration-secret", "real secret must not enter the sandbox")

	seen := rec.got("Authorization")
	require.Len(t, seen, 1)
	assert.Equal(t, "Bearer integration-secret", seen[0], "real credential injected on the wire")
}

// TestCurb_Inject_HeaderAgnostic confirms the same binding works for a different
// auth header (x-api-key, as Anthropic uses) with no header configured.
func TestCurb_Inject_HeaderAgnostic(t *testing.T) {
	requireProxyNS(t)

	rec := &headerRecorder{}
	cert, caPEM := upstreamTLS(t, []string{"localhost"})
	port := startTLSServer(t, cert, rec.handler())

	caFile := filepath.Join(t.TempDir(), "upstream-ca.pem")
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o644))

	url := fmt.Sprintf("https://localhost:%s/", port)
	script := fmt.Sprintf(
		"curl -sf --connect-timeout 10 -H \"x-api-key: $DEMO_KEY\" %s; echo \" a=$?\"", url)

	cmd := exec.Command(curbBin, "--write", "*", "--exec", "*",
		"--host-loopback",
		"--inject-header", "DEMO_KEY=localhost",
		"--", "sh", "-c", script)
	cmd.Env = append(envWithout("DEMO_KEY", "SSL_CERT_FILE"),
		"DEMO_KEY=sk-ant-real-integration",
		"SSL_CERT_FILE="+caFile,
	)

	out, err := cmd.CombinedOutput()
	outStr := filterCurbOutput(string(out))
	require.NoError(t, err, "sandboxed curl failed: %s", outStr)
	assert.Contains(t, outStr, "a=0")

	seen := rec.got("x-api-key")
	require.Len(t, seen, 1)
	assert.Equal(t, "sk-ant-real-integration", seen[0], "x-api-key placeholder replaced with real value")
}
