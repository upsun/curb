package netstack

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	httpMaxRead     = 8192
	httpReadTimeout = 10 * time.Second
	http403Response = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
)

// parseHTTPHost extracts the Host header value from an HTTP request.
// It returns the hostname (port stripped), the offset of the end of headers,
// and any error.
func parseHTTPHost(data []byte) (host string, headerEnd int, err error) {
	// Find end of headers.
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx < 0 {
		return "", 0, fmt.Errorf("no header terminator found")
	}
	headerEnd = idx + 4

	// Parse headers line by line looking for Host.
	headers := string(data[:idx])
	for line := range strings.SplitSeq(headers, "\r\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "host") {
			host = strings.TrimSpace(v)
			// Strip port if present.
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			return host, headerEnd, nil
		}
	}
	return "", headerEnd, fmt.Errorf("no Host header found")
}

// handleHTTPConnection reads up to 8KB from local to find an HTTP Host header,
// checks it against the filter, and either relays the connection or sends 403.
func handleHTTPConnection(local net.Conn, dst string, filter *FilterConfig) {
	defer func() { _ = local.Close() }()

	_ = local.SetReadDeadline(time.Now().Add(httpReadTimeout))
	buf := make([]byte, httpMaxRead)
	n, err := local.Read(buf)
	if err != nil || n == 0 {
		return
	}
	data := buf[:n]

	host, _, parseErr := parseHTTPHost(data)
	if parseErr != nil {
		filter.Logger.Event("http_request", dst, "blocked", "no_host")
		_, _ = local.Write([]byte(http403Response))
		return
	}

	if !filter.Check(host) {
		filter.Logger.Event("http_request", host, "blocked", "domain")
		_, _ = local.Write([]byte(http403Response))
		return
	}

	// Clear deadline for relay.
	_ = local.SetReadDeadline(time.Time{})

	remote, dialErr := net.DialTimeout("tcp", dst, tcpDialTimeout)
	if dialErr != nil {
		filter.Logger.Warn("http forward %s: %v", dst, dialErr)
		return
	}

	// Write the buffered data to remote before relaying.
	if _, err := remote.Write(data); err != nil {
		filter.Logger.Warn("http forward write %s: %v", dst, err)
		_ = remote.Close()
		return
	}

	relay(local, remote, dst, filter.Logger)
}
