package proxy

import (
	"bufio"
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
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/upsun/curb/policy"
)

// CA is a per-run certificate authority used to mint leaf certificates for the
// hosts whose TLS the injecting proxy terminates. It is trusted only inside one
// sandbox: even if the action reads the key, all it can do is MITM itself.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu     sync.RWMutex
	leaves map[string]*tls.Certificate
}

// NewCA generates an in-memory EC certificate authority. Generating the CA and
// signing leaves on demand is sub-millisecond.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca key: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "curb per-run CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse ca: %w", err)
	}
	return &CA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves:  map[string]*tls.Certificate{},
	}, nil
}

// CertPEM returns the CA certificate in PEM form, for injection into the
// action's trust store (SSL_CERT_FILE / GIT_SSL_CAINFO / ...).
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// leafFor returns a leaf certificate for host, signed by the CA. Leaves are
// cached per host for the life of the run. Signing happens without the lock
// held, so a cache hit for one host never blocks behind a sign for another.
func (ca *CA) leafFor(host string) (*tls.Certificate, error) {
	ca.mu.RLock()
	c := ca.leaves[host]
	ca.mu.RUnlock()
	if c != nil {
		return c, nil
	}
	leaf, err := ca.signLeaf(host)
	if err != nil {
		return nil, err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if existing := ca.leaves[host]; existing != nil {
		return existing, nil // another goroutine won the race; reuse its leaf
	}
	ca.leaves[host] = leaf
	return leaf, nil
}

// signLeaf mints a fresh leaf certificate for host. It holds no lock.
func (ca *CA) signLeaf(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leafCert}, nil
}

// Injection is a credential bound to a destination host: on requests the proxy
// forwards to that host, it replaces every occurrence of Placeholder in the
// request header values with Value, and does so for no other host. The sandbox
// holds only Placeholder; Value (the real credential) is parent-only.
type Injection struct {
	Placeholder string
	Value       string
}

// Injector terminates TLS for bound destinations and injects their credentials.
// A destination without a binding is not terminated — the Handler relays it as
// passthrough, so a credential is never stapled to a destination it was not
// provisioned for (the central correctness property). Bindings are keyed by
// host:port: the credential is injected only when both match.
type Injector struct {
	CA *CA
	// Upstream round-trips the decrypted, credential-injected request to the
	// real origin over a fresh TLS connection. Defaults to system-roots TLS;
	// tests override it to reach local servers.
	Upstream http.RoundTripper

	byTarget   map[string][]Injection // key: net.JoinHostPort(host, port)
	boundHosts map[string]struct{}    // host only, for the plain-HTTP refusal
}

// NewInjector creates an injector backed by the per-run CA. Its upstream
// transport uses the same dial and TLS-handshake timeouts as passthrough
// traffic so an injected request cannot hang indefinitely tying up a goroutine.
func NewInjector(ca *CA) *Injector {
	return &Injector{
		CA: ca,
		Upstream: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: dialTimeout}).DialContext,
			TLSHandshakeTimeout: dialTimeout,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		},
		byTarget:   map[string][]Injection{},
		boundHosts: map[string]struct{}{},
	}
}

// Bind adds a header injection for a destination host:port. Multiple headers
// may be bound to the same target.
func (in *Injector) Bind(host, port string, inj Injection) {
	host = normalizeHost(host)
	key := net.JoinHostPort(host, port)
	in.byTarget[key] = append(in.byTarget[key], inj)
	in.boundHosts[host] = struct{}{}
}

// binding returns the injections bound to host:port, if any.
func (in *Injector) binding(host, port string) ([]Injection, bool) {
	if in == nil {
		return nil, false // nil-safe so callers need no separate guard
	}
	injs, ok := in.byTarget[net.JoinHostPort(normalizeHost(host), port)]
	return injs, ok
}

// hasHost reports whether any binding exists for host on any port. The
// plain-HTTP path uses it to refuse cleartext to a host that holds a
// credential, regardless of the bound port.
func (in *Injector) hasHost(host string) bool {
	if in == nil {
		return false
	}
	_, ok := in.boundHosts[normalizeHost(host)]
	return ok
}

// normalizeHost canonicalizes a host for binding keys: an IP literal to its
// canonical form, otherwise a lowercased hostname. The binding side and the
// proxy lookup must agree, including when a client addresses an IP directly.
func normalizeHost(host string) string {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	return policy.NormalizeHost(host)
}

// injectCONNECT terminates the client's TLS with a per-run leaf for host,
// then forwards each decrypted request to the real upstream with the bound
// credential injected.
func (h *Handler) injectCONNECT(w http.ResponseWriter, host, port string, injs []Injection) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "curb: hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		h.logEvent("proxy_inject", host, "error", err.Error())
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	h.logEvent("proxy_inject", host, "allowed", "")
	if err := h.Injector.Serve(clientConn, host, port, injs); err != nil {
		h.logEvent("proxy_inject", host, "error", err.Error())
	}
}

// Serve terminates the client's TLS with a per-run leaf for host, then forwards
// each decrypted request to the real upstream with the bound credential
// injected. It is the shared injection path for both the HTTP CONNECT and the
// SOCKS5 egress routes; the caller has already accepted the connection (written
// the CONNECT 200 or the SOCKS5 success reply).
func (in *Injector) Serve(client net.Conn, host, port string, injs []Injection) error {
	// The binding matched on a normalized host (case-folded, no trailing dot,
	// canonical IP); mint the leaf and route upstream on the same form so the
	// cert, SNI, and Host header all agree.
	host = normalizeHost(host)
	leaf, err := in.CA.leafFor(host)
	if err != nil {
		return fmt.Errorf("leaf: %w", err)
	}
	tlsConn := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}
	defer func() { _ = tlsConn.Close() }()

	in.serveInjected(tlsConn, host, port, injs)
	return nil
}

// serveInjected reads requests off the decrypted client stream and forwards
// each to the upstream with the bound credentials set, relaying the response.
func (in *Injector) serveInjected(client net.Conn, host, port string, injs []Injection) {
	rt := in.Upstream
	// authority is the upstream the request is bound to. Drop the default
	// https port so the Host header matches what a direct client would send.
	authority := host
	if port != "443" {
		authority = net.JoinHostPort(host, port)
	}
	br := bufio.NewReader(client)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		// Strip hop-by-hop headers first so the client cannot smuggle a
		// placeholder past substitution by naming a header in Connection.
		stripHopByHop(req.Header)
		// Replace the placeholder with the real credential wherever the client
		// placed it among the request headers. The sandbox never holds the real
		// value, so this is where the credential is first introduced. Header
		// values only: bodies and the request URI are left untouched.
		replaceInHeaders(req.Header, injs)
		req.URL.Scheme = "https"
		req.URL.Host = authority
		// Align the Host header with the upstream we dial; the client may have
		// sent a placeholder or an incorrect port.
		req.Host = authority
		req.RequestURI = ""

		resp, err := rt.RoundTrip(req)
		if err != nil {
			writeGatewayError(client)
			return
		}
		werr := resp.Write(client)
		_ = resp.Body.Close()
		if werr != nil {
			return
		}
	}
}

// replaceInHeaders substitutes each binding's placeholder with its real value in
// every request header value. Placement is the client's choice — Authorization:
// Bearer <ph>, x-api-key: <ph>, or any other header all work, so the proxy needs
// no knowledge of the host's auth scheme.
func replaceInHeaders(hdr http.Header, injs []Injection) {
	for _, values := range hdr {
		for i, v := range values {
			for _, inj := range injs {
				v = strings.ReplaceAll(v, inj.Placeholder, inj.Value)
			}
			values[i] = v
		}
	}
}

func writeGatewayError(c net.Conn) {
	_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
}
