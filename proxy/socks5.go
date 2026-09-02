package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socks5Version = 0x05

	// Authentication methods.
	socks5AuthNone         = 0x00
	socks5AuthNoAcceptable = 0xFF

	// Commands.
	socks5CmdConnect = 0x01

	// Address types.
	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	// Reply codes.
	socks5RepSuccess         = 0x00
	socks5RepGeneralFailure  = 0x01
	socks5RepNotAllowed      = 0x02
	socks5RepHostUnreachable = 0x04
	socks5RepCmdNotSupported = 0x07
)

// SOCKS5Server handles SOCKS5 CONNECT requests with domain/IP filtering.
type SOCKS5Server struct {
	FilterBase
	// Injector, when set, terminates TLS and injects a bound credential for
	// hosts it has a binding for. Hosts without a binding are relayed as-is.
	Injector *Injector
}

// Serve accepts connections from ln and handles each in a goroutine.
func (s *SOCKS5Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.HandleConn(conn)
	}
}

// HandleConn processes a single SOCKS5 connection.
func (s *SOCKS5Server) HandleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// 1. Method negotiation.
	// Client: [VER, NMETHODS, METHODS...]
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socks5Version {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// We only support no-auth.
	hasNoAuth := slices.Contains(methods, socks5AuthNone)
	if !hasNoAuth {
		_, _ = conn.Write([]byte{socks5Version, socks5AuthNoAcceptable})
		return
	}
	// Reply: no auth required.
	if _, err := conn.Write([]byte{socks5Version, socks5AuthNone}); err != nil {
		return
	}

	// 2. Request.
	// Client: [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[0] != socks5Version {
		return
	}
	if req[1] != socks5CmdConnect {
		s.sendReply(conn, socks5RepCmdNotSupported)
		return
	}

	host, port, err := readSOCKS5Address(conn, req[3])
	if err != nil {
		s.sendReply(conn, socks5RepGeneralFailure)
		return
	}

	// 3. Check target against domain/IP policy.
	if !s.CheckTarget(host) {
		s.sendReply(conn, socks5RepNotAllowed)
		s.logEvent("socks5_connect", net.JoinHostPort(host, port), "blocked", "policy")
		return
	}

	// 4. A bound destination is TLS-terminated so the credential can be
	// injected, matching the HTTP CONNECT path; everything else is relayed
	// below. The binding matches on host:port — a name from a socks5h client
	// (curb advertises socks5h://) or an IP literal when the target is an IP.
	target := net.JoinHostPort(host, port)
	if injs, ok := s.Injector.binding(host, port); ok {
		s.sendReply(conn, socks5RepSuccess)
		s.logEvent("socks5_inject", target, "allowed", "")
		if err := s.Injector.Serve(conn, host, port, injs); err != nil {
			s.logEvent("socks5_inject", target, "error", err.Error())
		}
		return
	}

	// 5. Dial the destination.
	remote, err := s.getDialer().Dial("tcp", target)
	if err != nil {
		s.sendReply(conn, socks5RepHostUnreachable)
		s.logEvent("socks5_connect", target, "error", "dial: "+err.Error())
		return
	}
	defer func() { _ = remote.Close() }()

	// 6. Success reply.
	s.sendReply(conn, socks5RepSuccess)
	s.logEvent("socks5_connect", target, "allowed", "")

	// 7. Relay.
	relay(conn, remote)
}

// readAddress reads the destination address from a SOCKS5 request.
func readSOCKS5Address(r io.Reader, atyp byte) (host, port string, err error) {
	switch atyp {
	case socks5AtypIPv4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", "", err
		}
		host = netip.AddrFrom4([4]byte(buf[:4])).String()
		port = fmt.Sprintf("%d", binary.BigEndian.Uint16(buf[4:]))

	case socks5AtypIPv6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", "", err
		}
		host = netip.AddrFrom16([16]byte(buf[:16])).String()
		port = fmt.Sprintf("%d", binary.BigEndian.Uint16(buf[16:]))

	case socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", "", err
		}
		buf := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", "", err
		}
		host = string(buf[:len(buf)-2])
		port = fmt.Sprintf("%d", binary.BigEndian.Uint16(buf[len(buf)-2:]))

	default:
		return "", "", fmt.Errorf("unsupported address type: %d", atyp)
	}
	return host, port, nil
}

// sendReply sends a SOCKS5 reply with the given status code.
// The bound address is always 0.0.0.0:0 (we don't expose real bind info).
func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte) {
	// VER, REP, RSV, ATYP(IPv4), BND.ADDR(0.0.0.0), BND.PORT(0)
	_, _ = conn.Write([]byte{
		socks5Version, rep, 0x00, socks5AtypIPv4,
		0, 0, 0, 0, // 0.0.0.0
		0, 0, // port 0
	})
}
