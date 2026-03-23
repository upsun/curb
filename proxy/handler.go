package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)


// Handler is an HTTP proxy handler that filters CONNECT (HTTPS) and plain
// HTTP requests by domain and IP allowlists. HTTPS uses passthrough
// tunneling: the proxy checks the CONNECT hostname, then relays the
// encrypted stream without terminating TLS.
type Handler struct {
	FilterBase
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleCONNECT(w, r)
		return
	}
	h.handleHTTP(w, r)
}

// handleCONNECT handles HTTPS CONNECT tunneling with passthrough relay.
// The domain is checked against the allowlist before tunneling. The proxy
// does not terminate TLS — the encrypted stream is relayed as-is.
func (h *Handler) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPort(r.Host, "443")
	if err != nil {
		http.Error(w, "curb: bad CONNECT target", http.StatusBadRequest)
		return
	}

	if !h.CheckTarget(host) {
		http.Error(w, "curb: domain not allowed: "+host, http.StatusForbidden)
		h.logEvent("proxy_connect", r.Host, "blocked", "domain")
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
		h.logEvent("proxy_connect", r.Host, "error", err.Error())
		return
	}
	defer func() { _ = clientConn.Close() }()

	target := net.JoinHostPort(host, port)
	remote, err := h.getDialer().Dial("tcp", target)
	if err != nil {
		h.logEvent("proxy_connect", r.Host, "error", "dial: "+err.Error())
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer func() { _ = remote.Close() }()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	h.logEvent("proxy_connect", r.Host, "allowed", "")

	relay(clientConn, remote)
}

// handleHTTP forwards plain HTTP requests.
func (h *Handler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPort(r.Host, "80")
	if err != nil {
		http.Error(w, "curb: bad host", http.StatusBadRequest)
		return
	}

	if !h.CheckTarget(host) {
		http.Error(w, "curb: domain not allowed: "+host, http.StatusForbidden)
		h.logEvent("proxy_http", r.Host, "blocked", "domain")
		return
	}

	// Dial the upstream (using request context for cancellation on client disconnect).
	target := net.JoinHostPort(host, port)
	upstream, err := h.getDialer().DialContext(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, "curb: upstream dial failed", http.StatusBadGateway)
		h.logEvent("proxy_http", r.Host, "error", "dial: "+err.Error())
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

	h.logEvent("proxy_http", r.Host, "allowed", "")

	relay(upstream, clientConn)
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
