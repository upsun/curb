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
	// Injector, when set, terminates TLS and injects a bound credential for
	// hosts it has a binding for. Hosts without a binding stay passthrough.
	Injector *Injector
}

// connEstablished is the response accepting a CONNECT request, written raw on
// the hijacked connection.
const connEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n"

// hijack takes over the client connection from the ResponseWriter, reporting
// failures under the given log event. The bufio.ReadWriter from Hijack is
// safely ignored on every proxy path: in the CONNECT flow no client data is
// buffered before the 200 response, and in the plain-HTTP flow the single
// request has already been fully read by net/http (pipelining through a
// forward proxy is not a real-world concern).
func (h *Handler) hijack(w http.ResponseWriter, event, target string) (net.Conn, bool) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "curb: hijack unsupported", http.StatusInternalServerError)
		return nil, false
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		h.logEvent(event, target, "error", err.Error())
		return nil, false
	}
	return conn, true
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
		http.Error(w, "curb: domain not allowed: "+host+" (see $CURB_SKILL_DIR/SKILL.md)", http.StatusForbidden)
		h.logEvent("proxy_connect", r.Host, "blocked", "domain")
		return
	}

	// A bound host is TLS-terminated so the credential can be injected;
	// everything else keeps the passthrough relay below.
	if injs, ok := h.Injector.binding(host, port); ok {
		h.injectCONNECT(w, host, port, injs)
		return
	}

	clientConn, ok := h.hijack(w, "proxy_connect", r.Host)
	if !ok {
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

	if _, err := clientConn.Write([]byte(connEstablished)); err != nil {
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
		http.Error(w, "curb: domain not allowed: "+host+" (see $CURB_SKILL_DIR/SKILL.md)", http.StatusForbidden)
		h.logEvent("proxy_http", r.Host, "blocked", "domain")
		return
	}

	// A credential is bound to this exact host:port but the request is plain
	// HTTP. Refuse rather than forward: injecting over cleartext would expose
	// the real credential. Other ports of the same host are relayed unchanged,
	// per the port-exact binding contract.
	if _, bound := h.Injector.binding(host, port); bound {
		http.Error(w, "curb: credential injection requires HTTPS for "+net.JoinHostPort(host, port), http.StatusBadGateway)
		h.logEvent("proxy_http", r.Host, "blocked", "inject-requires-https")
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

	stripHopByHop(r.Header)
	r.Header.Set("Connection", "close")

	// Write the request to the upstream.
	r.RequestURI = ""
	if err := r.Write(upstream); err != nil {
		http.Error(w, "curb: upstream write failed", http.StatusBadGateway)
		return
	}

	// Hijack and relay the response.
	clientConn, ok := h.hijack(w, "proxy_http", r.Host)
	if !ok {
		return
	}
	defer func() { _ = clientConn.Close() }()

	h.logEvent("proxy_http", r.Host, "allowed", "")

	relay(upstream, clientConn)
}

// stripHopByHop removes hop-by-hop headers (RFC 7230 §6.1) before forwarding a
// request upstream, including any named in the Connection header. This keeps
// proxy-specific headers such as Proxy-Authorization from leaking to the origin.
func stripHopByHop(h http.Header) {
	for _, connHdr := range h.Values("Connection") {
		for part := range strings.SplitSeq(connHdr, ",") {
			h.Del(strings.TrimSpace(part))
		}
	}
	h.Del("Connection")
	h.Del("Keep-Alive")
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authorization")
	h.Del("TE")
	h.Del("Trailer")
	h.Del("Upgrade")
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
