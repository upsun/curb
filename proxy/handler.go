package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/upsun/curb/clog"
)

const (
	dialTimeout = 10 * time.Second
)

// Handler is an HTTP MITM proxy handler that filters CONNECT (HTTPS) and
// plain HTTP requests by domain and IP allowlists.
type Handler struct {
	DomainCheck func(string) bool
	IPCheck     func(netip.Addr) bool
	CertCache   *CertCache
	Logger      *clog.Logger
	AllowHTTP   bool

	// Dialer overrides the default dialer for outbound connections.
	// If nil, net.Dialer{Timeout: dialTimeout} is used.
	Dialer *net.Dialer
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleCONNECT(w, r)
		return
	}
	h.handleHTTP(w, r)
}

// handleCONNECT handles HTTPS CONNECT tunneling with TLS MITM.
func (h *Handler) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPort(r.Host, "443")
	if err != nil {
		http.Error(w, "curb: bad CONNECT target", http.StatusBadRequest)
		return
	}

	if !h.checkTarget(host) {
		http.Error(w, "curb: domain not allowed: "+host, http.StatusForbidden)
		h.log("proxy_connect", r.Host, "blocked", "domain")
		return
	}

	// Hijack the client connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "curb: hijack unsupported", http.StatusInternalServerError)
		return
	}
	// The bufio.ReadWriter from Hijack is safely ignored: no client data
	// is buffered before the 200 response in the CONNECT flow.
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		h.log("proxy_connect", r.Host, "error", err.Error())
		return
	}
	defer func() { _ = clientConn.Close() }()

	// Send 200 to the client.
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// TLS handshake with client using generated cert.
	cert, err := h.CertCache.certFor(host)
	if err != nil {
		h.log("proxy_connect", r.Host, "error", "cert: "+err.Error())
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	})
	if err := tlsClient.Handshake(); err != nil {
		h.log("proxy_connect", r.Host, "error", "client handshake: "+err.Error())
		return
	}
	defer func() { _ = tlsClient.Close() }()

	// Connect to real destination.
	target := net.JoinHostPort(host, port)
	tlsRemote, err := tls.DialWithDialer(h.dialer(), "tcp", target, &tls.Config{
		ServerName: host,
	})
	if err != nil {
		h.log("proxy_connect", r.Host, "error", "dial: "+err.Error())
		return
	}
	defer func() { _ = tlsRemote.Close() }()

	h.log("proxy_connect", r.Host, "allowed", "")

	relay(tlsClient, tlsRemote)
}

// handleHTTP forwards plain HTTP requests.
func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.AllowHTTP {
		http.Error(w, "curb: plain HTTP not allowed (use --allow-http)", http.StatusForbidden)
		h.log("proxy_http", r.Host, "blocked", "http-disabled")
		return
	}

	host, port, err := splitHostPort(r.Host, "80")
	if err != nil {
		http.Error(w, "curb: bad host", http.StatusBadRequest)
		return
	}

	if !h.checkTarget(host) {
		http.Error(w, "curb: domain not allowed: "+host, http.StatusForbidden)
		h.log("proxy_http", r.Host, "blocked", "domain")
		return
	}

	// Dial the upstream (using request context for cancellation on client disconnect).
	target := net.JoinHostPort(host, port)
	upstream, err := h.dialer().DialContext(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, "curb: upstream dial failed", http.StatusBadGateway)
		h.log("proxy_http", r.Host, "error", "dial: "+err.Error())
		return
	}
	defer func() { _ = upstream.Close() }()

	// Strip hop-by-hop headers before forwarding (RFC 7230 §6.1).
	// Parse Connection header for additional hop-by-hop headers to remove.
	for _, connHdr := range r.Header.Values("Connection") {
		for part := range strings.SplitSeq(connHdr, ",") {
			r.Header.Del(strings.TrimSpace(part))
		}
	}
	r.Header.Del("Connection")
	r.Header.Del("Keep-Alive")
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("TE")
	r.Header.Del("Trailer")
	r.Header.Del("Upgrade")
	r.Header.Set("Connection", "close")

	// Write the request to the upstream.
	r.RequestURI = ""
	if err := r.Write(upstream); err != nil {
		http.Error(w, "curb: upstream write failed", http.StatusBadGateway)
		return
	}

	// Hijack and relay the response.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "curb: hijack unsupported", http.StatusInternalServerError)
		return
	}
	// The bufio.ReadWriter from Hijack is safely ignored: the single
	// request has already been fully read by net/http, and HTTP pipelining
	// through a forward proxy is not a real-world concern.
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = clientConn.Close() }()

	h.log("proxy_http", r.Host, "allowed", "")

	relay(upstream, clientConn)
}

// checkTarget checks whether a target hostname or IP is allowed.
func (h *Handler) checkTarget(host string) bool {
	// Try as IP first.
	if addr, err := netip.ParseAddr(host); err == nil {
		if h.IPCheck != nil {
			return h.IPCheck(addr)
		}
		return false
	}
	// Domain check.
	if h.DomainCheck != nil {
		return h.DomainCheck(host)
	}
	return false
}

// splitHostPort splits host:port, using defaultPort if no port is present.
func splitHostPort(hostport, defaultPort string) (string, string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port: treat the whole thing as host.
		host = hostport
		port = defaultPort
	}
	if host == "" {
		return "", "", fmt.Errorf("empty host")
	}
	return host, port, nil
}

// writeCloser is implemented by net.TCPConn, tls.Conn, and other types that
// support half-close (sending a FIN / close_notify without closing the read
// side).
type writeCloser interface {
	CloseWrite() error
}

// relay copies data bidirectionally between two connections.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// Signal write-done to unblock the other direction.
		if hc, ok := dst.(writeCloser); ok {
			_ = hc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

func (h *Handler) dialer() *net.Dialer {
	if h.Dialer != nil {
		return h.Dialer
	}
	return &net.Dialer{Timeout: dialTimeout}
}

func (h *Handler) log(event, target, action, reason string) {
	if h.Logger == nil {
		return
	}
	h.Logger.Event(event, target, action, reason)
}
