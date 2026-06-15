package proxy

import (
	"bufio"
	"context"
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
	"strings"
	"sync"
	"time"
)

// CA is a per-run certificate authority used to mint leaf certificates for the
// hosts whose TLS the injecting proxy terminates. It is trusted only inside one
// sandbox: even if the action reads the key, all it can do is MITM itself.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu     sync.Mutex
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
// cached per host for the life of the run.
func (ca *CA) leafFor(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.leaves[host]; ok {
		return c, nil
	}
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
	leaf := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leafCert}
	ca.leaves[host] = leaf
	return leaf, nil
}

// Injection is a credential bound to a destination host: the proxy sets Header
// to Value on requests it forwards to that host, and to no other host.
type Injection struct {
	Header string
	Value  string
}

// Injector terminates TLS for bound hosts and injects their credentials. A host
// without a binding is not terminated — the Handler relays it as passthrough,
// so a credential is never stapled to a destination it was not provisioned for
// (the central correctness property).
type Injector struct {
	CA *CA
	// Upstream round-trips the decrypted, credential-injected request to the
	// real origin over a fresh TLS connection. Defaults to system-roots TLS;
	// tests override it to reach local servers.
	Upstream http.RoundTripper

	byHost map[string][]Injection
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
		byHost: map[string][]Injection{},
	}
}

// Bind adds a header injection for a destination host. Multiple headers may be
// bound to the same host.
func (in *Injector) Bind(host string, inj Injection) {
	host = normalizeHost(host)
	in.byHost[host] = append(in.byHost[host], inj)
}

func (in *Injector) binding(host string) ([]Injection, bool) {
	injs, ok := in.byHost[normalizeHost(host)]
	return injs, ok
}

// normalizeHost lowercases and trims a trailing dot so binding keys match
// CONNECT targets regardless of case or root-label dot (api.example.com,
// API.EXAMPLE.COM, and api.example.com. are the same host).
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
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

	leaf, err := h.Injector.CA.leafFor(host)
	if err != nil {
		h.logEvent("proxy_inject", host, "error", "leaf: "+err.Error())
		return
	}
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		h.logEvent("proxy_inject", host, "error", "tls handshake: "+err.Error())
		return
	}
	defer func() { _ = tlsConn.Close() }()

	h.logEvent("proxy_inject", host, "allowed", "")
	h.serveInjected(tlsConn, host, port, injs)
}

// serveInjected reads requests off the decrypted client stream and forwards
// each to the upstream with the bound credentials set, relaying the response.
func (h *Handler) serveInjected(client net.Conn, host, port string, injs []Injection) {
	rt := h.Injector.Upstream
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
		// Strip hop-by-hop headers first so the client cannot drop an injected
		// header by naming it in Connection.
		stripHopByHop(req.Header)
		// Overwrite any client-supplied values: the sandbox holds only a
		// placeholder and must not pre-empt the real credential.
		for _, inj := range injs {
			req.Header.Set(inj.Header, inj.Value)
		}
		req.URL.Scheme = "https"
		req.URL.Host = authority
		// Align the Host header with the upstream we dial; the client may have
		// sent a placeholder or an incorrect port.
		req.Host = authority
		req.RequestURI = ""

		resp, err := rt.RoundTrip(req.WithContext(context.Background()))
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

func writeGatewayError(c net.Conn) {
	_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
}
