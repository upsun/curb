package proxy

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSOCKS5Server_ConnectDomain(t *testing.T) {
	// Start a simple TCP echo server as the "upstream".
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			conn, acceptErr := echoLn.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	_, echoPort, _ := net.SplitHostPort(echoLn.Addr().String())

	srv := &SOCKS5Server{
		DomainCheck: func(domain string) bool {
			return domain == "localhost"
		},
		Dialer: &net.Dialer{Timeout: 2 * time.Second},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.Serve(ln) }()

	// Connect via SOCKS5 with domain name.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Handshake: no-auth.
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x05, 0x00}, reply)

	// CONNECT to localhost:echoPort.
	host := "localhost"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	portNum := mustParsePort(t, echoPort)
	req = append(req, byte(portNum>>8), byte(portNum))
	_, err = conn.Write(req)
	require.NoError(t, err)

	// Read reply.
	repHeader := make([]byte, 10) // VER + REP + RSV + ATYP + IPv4(4) + PORT(2)
	_, err = io.ReadFull(conn, repHeader)
	require.NoError(t, err)
	assert.Equal(t, byte(0x00), repHeader[1], "expected success reply")

	// Send data through the tunnel.
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	buf := make([]byte, 5)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf))
}

func TestSOCKS5Server_BlockedDomain(t *testing.T) {
	srv := &SOCKS5Server{
		DomainCheck: func(domain string) bool {
			return false // Block everything.
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.Serve(ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Handshake.
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)

	// CONNECT to blocked domain.
	host := "blocked.example.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, 0x00, 0x50) // port 80
	_, err = conn.Write(req)
	require.NoError(t, err)

	// Expect rejection (reply code 0x02 = not allowed).
	repHeader := make([]byte, 10)
	_, err = io.ReadFull(conn, repHeader)
	require.NoError(t, err)
	assert.Equal(t, byte(socks5RepNotAllowed), repHeader[1])
}

func TestSOCKS5Server_ConnectIPv4(t *testing.T) {
	// Start echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			conn, acceptErr := echoLn.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	_, echoPort, _ := net.SplitHostPort(echoLn.Addr().String())

	srv := &SOCKS5Server{
		IPCheck: func(addr netip.Addr) bool {
			return addr.IsLoopback()
		},
		Dialer: &net.Dialer{Timeout: 2 * time.Second},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.Serve(ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Handshake.
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)

	// CONNECT with IPv4 address type.
	portNum := mustParsePort(t, echoPort)
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, byte(portNum >> 8), byte(portNum)}
	_, err = conn.Write(req)
	require.NoError(t, err)

	repHeader := make([]byte, 10)
	_, err = io.ReadFull(conn, repHeader)
	require.NoError(t, err)
	assert.Equal(t, byte(0x00), repHeader[1], "expected success reply")

	// Verify data flows.
	_, err = conn.Write([]byte("ipv4"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ipv4", string(buf))
}

func TestSOCKS5Server_UnsupportedCommand(t *testing.T) {
	srv := &SOCKS5Server{
		DomainCheck: func(string) bool { return true },
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.Serve(ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Handshake.
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)

	// BIND command (0x02) — not supported.
	req := []byte{0x05, 0x02, 0x00, 0x03, 0x09}
	req = append(req, []byte("localhost")...)
	req = append(req, 0x00, 0x50)
	_, err = conn.Write(req)
	require.NoError(t, err)

	repHeader := make([]byte, 10)
	_, err = io.ReadFull(conn, repHeader)
	require.NoError(t, err)
	assert.Equal(t, byte(socks5RepCmdNotSupported), repHeader[1])
}

func TestSOCKS5Server_ConcurrentConnections(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = echoLn.Close() }()
	go func() {
		for {
			conn, acceptErr := echoLn.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	_, echoPort, _ := net.SplitHostPort(echoLn.Addr().String())

	srv := &SOCKS5Server{
		DomainCheck: func(string) bool { return true },
		Dialer:      &net.Dialer{Timeout: 2 * time.Second},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.Serve(ln) }()

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, dialErr := net.Dial("tcp", ln.Addr().String())
			if dialErr != nil {
				return
			}
			defer func() { _ = conn.Close() }()

			// Handshake + CONNECT.
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
			reply := make([]byte, 2)
			_, _ = io.ReadFull(conn, reply)

			host := "localhost"
			portNum := mustParsePort(t, echoPort)
			req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
			req = append(req, []byte(host)...)
			req = append(req, byte(portNum>>8), byte(portNum))
			_, _ = conn.Write(req)

			repHeader := make([]byte, 10)
			_, _ = io.ReadFull(conn, repHeader)
			if repHeader[1] != 0x00 {
				return
			}

			msg := []byte("ping")
			_, _ = conn.Write(msg)
			buf := make([]byte, 4)
			_, _ = io.ReadFull(conn, buf)
			assert.Equal(t, "ping", string(buf))
		}(i)
	}
	wg.Wait()
}

func mustParsePort(t *testing.T, port string) uint16 {
	t.Helper()
	p, err := net.LookupPort("tcp", port)
	require.NoError(t, err)
	return uint16(p)
}
