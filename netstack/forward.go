package netstack

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/upsun/curb/clog"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	tcpDialTimeout     = 10 * time.Second
	udpIdleTimeout     = 30 * time.Second
	dnsForwardTimeout  = 5 * time.Second
	maxTCPInFlight     = 1024
	dnsPort            = 53
	httpPort           = 80
	tlsPort            = 443
	udpMaxPacketSize   = 65535
	dnsMaxResponseSize = 4096 // EDNS0 max; avoids 64KB allocation per query.
)

// newDNSFilter creates a DNSFilter from a FilterConfig, or returns nil if
// filtering is not active. When ECHMode is ECHStrip, DNS ECH stripping and
// IP caching are enabled, and the filter's checkIP is wired to the cache.
func newDNSFilter(filter *FilterConfig) *DNSFilter {
	if filter == nil || filter.Check == nil {
		return nil
	}
	df := &DNSFilter{Check: filter.Check, Logger: filter.Logger}
	if filter.ECHMode == ECHStrip {
		df.stripECH = true
	}
	// Always wire the IP cache so loopback connections to DNS-resolved
	// IPs can be allowed without explicit --domains localhost.
	filter.checkIP = df.isResolvedIP
	return df
}

// isLoopback reports whether the address is in 127.0.0.0/8.
func isLoopback(addr tcpip.Address) bool {
	b := addr.As4()
	return b[0] == 127
}

// filterLogger returns the Logger from filter, or nil.
func filterLogger(filter *FilterConfig) *clog.Logger {
	if filter == nil {
		return nil
	}
	return filter.Logger
}

// rejectReason returns a non-empty string if the TCP connection can be
// rejected with RST before accepting, based on port and IP alone. The
// returned string describes why the connection was rejected (for logging).
func rejectReason(id stack.TransportEndpointID, filter *FilterConfig, dnsFilter *DNSFilter) string {
	// No filtering active: accept everything.
	if filter == nil {
		return ""
	}

	loopback := isLoopback(id.LocalAddress)

	// Localhost-only mode (filter set, no Check): reject all non-loopback.
	if filter.Check == nil {
		if loopback {
			return ""
		}
		return "localhost-only mode"
	}

	// Loopback: reject if not allowed (except DNS, which is always filtered).
	if loopback {
		if id.LocalPort == dnsPort && dnsFilter != nil {
			return ""
		}
		if filter.allowsLoopback(addrString(id.LocalAddress)) {
			return ""
		}
		return "loopback not allowed"
	}

	// Domain filtering active: only accept ports that need data inspection.
	if dnsFilter != nil {
		switch id.LocalPort {
		case dnsPort, tlsPort:
			return ""
		case httpPort:
			if filter.AllowHTTP {
				return ""
			}
			return "port 80 disabled"
		default:
			return "port not allowed"
		}
	}

	return ""
}

// setupTCPForwarding installs a TCP forwarder that proxies connections to the real network.
// If filter is active, traffic is routed by port:
// 53 → DNS filter, 443 → TLS SNI filter, 80 → HTTP filter (if AllowHTTP), others → RST.
// Loopback destinations (127.0.0.0/8) are forwarded to the host if AllowLocalhost is set.
func setupTCPForwarding(s *stack.Stack, filter *FilterConfig, dnsFilter *DNSFilter) {
	logger := filterLogger(filter)
	fwd := tcp.NewForwarder(s, 0, maxTCPInFlight, func(r *tcp.ForwarderRequest) {
		id := r.ID()

		// Early rejection: send TCP RST for connections that can be blocked
		// by port/IP alone, without reading data.
		if reason := rejectReason(id, filter, dnsFilter); reason != "" {
			dst := net.JoinHostPort(addrString(id.LocalAddress), fmt.Sprintf("%d", id.LocalPort))
			logger.Event("tcp_connect", dst, "blocked", reason)
			r.Complete(true) // TCP RST
			return
		}

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			if logger.IsDebug() {
				logger.Debug("tcp endpoint failed: %s:%d → %s:%d: %v",
					addrString(id.RemoteAddress), id.RemotePort,
					addrString(id.LocalAddress), id.LocalPort, err)
			}
			r.Complete(true)
			return
		}
		r.Complete(false)

		dstIP := addrString(id.LocalAddress)
		dst := net.JoinHostPort(dstIP, fmt.Sprintf("%d", id.LocalPort))
		local := gonet.NewTCPConn(&wq, ep)
		if logger.IsDebug() {
			logger.Debug("tcp accept: %s:%d → %s", addrString(id.RemoteAddress), id.RemotePort, dst)
		}

		// Loopback traffic handling (loopback rejections handled above).
		if isLoopback(id.LocalAddress) {
			if id.LocalPort == dnsPort && dnsFilter != nil {
				go dnsFilter.handleTCPQuery(local, dst)
				return
			}
			hostDst := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", id.LocalPort))
			go forwardTCP(local, hostDst, logger)
			return
		}

		// When filtering is active, route by port.
		if dnsFilter != nil {
			switch id.LocalPort {
			case dnsPort:
				go dnsFilter.handleTCPQuery(local, dst)
			case tlsPort:
				go handleTLSConnection(local, dst, filter)
			case httpPort:
				go handleHTTPConnection(local, dst, filter)
			default:
				// Should not reach here: rejectReason handles non-standard ports.
				_ = local.Close()
			}
			return
		}

		// No filtering: forward directly.
		remote, dialErr := net.DialTimeout("tcp", dst, tcpDialTimeout)
		if dialErr != nil {
			logger.Warn("tcp forward %s: %v", dst, dialErr)
			_ = local.Close()
			return
		}

		go relay(local, remote, dst, logger)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

// forwardTCP dials the destination and relays data bidirectionally.
func forwardTCP(local net.Conn, dst string, logger *clog.Logger) {
	remote, err := net.DialTimeout("tcp", dst, tcpDialTimeout)
	if err != nil {
		logger.Warn("localhost forward %s: %v", dst, err)
		_ = local.Close()
		return
	}
	relay(local, remote, dst, logger)
}

// setupUDPForwarding installs a UDP forwarder that proxies packets to the real network.
// If dnsFilter is non-nil, only UDP port 53 (DNS) is forwarded; all other UDP is dropped.
// Loopback DNS is always forwarded; other loopback UDP requires AllowLocalhost.
func setupUDPForwarding(s *stack.Stack, filter *FilterConfig, dnsFilter *DNSFilter) {
	logger := filterLogger(filter)
	fwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}

		dstIP := addrString(id.LocalAddress)
		dst := net.JoinHostPort(dstIP, fmt.Sprintf("%d", id.LocalPort))
		local := gonet.NewUDPConn(&wq, ep)

		// Loopback traffic handling.
		if isLoopback(id.LocalAddress) {
			if id.LocalPort == dnsPort && dnsFilter != nil {
				go dnsFilter.handleQuery(local, dst)
				return true
			}
			if filter.allowsLoopback(dstIP) {
				hostDst := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", id.LocalPort))
				remote, dialErr := net.Dial("udp", hostDst)
				if dialErr != nil {
					logger.Warn("localhost udp forward %s: %v", hostDst, dialErr)
					ep.Close()
					return true
				}
				go relayUDP(local, remote)
				return true
			}
			logger.Debug("udp loopback dropped: %s", dst)
			_ = local.Close()
			return true
		}

		// When filtering is active, only DNS is allowed.
		if dnsFilter != nil {
			if id.LocalPort == dnsPort {
				go dnsFilter.handleQuery(local, dst)
			} else {
				logger.Debug("udp port %d dropped (not 53): %s", id.LocalPort, dst)
				_ = local.Close()
			}
			return true
		}

		// If a filter is set but has no Check function (localhost-only mode),
		// drop all non-loopback traffic.
		if filter != nil {
			_ = local.Close()
			return true
		}

		remote, dialErr := net.Dial("udp", dst)
		if dialErr != nil {
			logger.Warn("udp forward %s: %v", dst, dialErr)
			ep.Close()
			return true
		}

		go relayUDP(local, remote)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
}

// relay copies data bidirectionally between two connections, then closes both.
func relay(a, b net.Conn, dst string, logger *clog.Logger) {
	logger.Debug("relay start: %s", dst)
	done := make(chan struct{})
	go func() {
		n, err := io.Copy(a, b)
		if err != nil {
			logger.Debug("relay remote→local: %s (%d bytes, err=%v)", dst, n, err)
		}
		close(done)
	}()
	n, err := io.Copy(b, a)
	if err != nil {
		logger.Debug("relay local→remote: %s (%d bytes, err=%v)", dst, n, err)
	}
	<-done
	_ = a.Close()
	_ = b.Close()
	logger.Debug("relay done: %s (%d bytes client→server)", dst, n)
}

// relayUDP copies data bidirectionally between a gonet UDPConn and a real net.Conn.
// It uses read deadlines for inactivity timeout since UDP is connectionless.
func relayUDP(local *gonet.UDPConn, remote net.Conn) {
	done := make(chan struct{})
	go func() {
		buf := make([]byte, udpMaxPacketSize)
		for {
			_ = remote.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, readErr := remote.Read(buf)
			if n > 0 {
				if _, writeErr := local.Write(buf[:n]); writeErr != nil {
					break
				}
			}
			if readErr != nil {
				break
			}
		}
		close(done)
	}()

	buf := make([]byte, udpMaxPacketSize)
	for {
		_ = local.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, readErr := local.Read(buf)
		if n > 0 {
			if _, writeErr := remote.Write(buf[:n]); writeErr != nil {
				break
			}
		}
		if readErr != nil {
			break
		}
	}
	<-done
	_ = local.Close()
	_ = remote.Close()
}

// addrString converts a tcpip.Address to a string representation.
func addrString(addr tcpip.Address) string {
	b := addr.As4()
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
