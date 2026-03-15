package netstack

import (
	"fmt"
	"io"
	"net"
	"net/netip"
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

// routeAction describes what to do with a connection.
type routeAction int

const (
	routeForward  routeAction = iota // Direct forward, no inspection.
	routeDNS                         // Route to DNS filter.
	routeTLS                         // Route to TLS SNI inspector.
	routeHTTP                        // Route to HTTP Host inspector.
	routeLoopback                    // Forward to host's localhost.
	routeDrop                        // Drop/reject connection.
)

// routeResult pairs an action with an optional drop reason.
type routeResult struct {
	action routeAction
	reason string // Non-empty only for routeDrop.
}

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

// toNetIP converts a gvisor tcpip.Address to a net/netip.Addr.
func toNetIP(addr tcpip.Address) (netip.Addr, bool) {
	if addr.Len() == 4 {
		return netip.AddrFrom4(addr.As4()), true
	}
	if addr.Len() == 16 {
		return netip.AddrFrom16(addr.As16()), true
	}
	return netip.Addr{}, false
}

// routeDecision determines the routing action for a connection based on
// destination address, port, and the active filter configuration.
func routeDecision(addr tcpip.Address, port uint16, filter *FilterConfig, dnsFilter *DNSFilter) routeResult {
	// No filtering active: forward everything.
	if filter == nil {
		return routeResult{action: routeForward}
	}

	// Localhost-only mode (filter set, no Check and no CheckIP).
	if filter.Check == nil && filter.CheckIP == nil {
		if isLoopback(addr) {
			return routeResult{action: routeLoopback}
		}
		return routeResult{action: routeDrop, reason: "localhost-only mode"}
	}

	// Loopback destinations need the 127.0.0.1 rewrite, so check before CheckIP.
	if isLoopback(addr) {
		if port == dnsPort && dnsFilter != nil {
			return routeResult{action: routeDNS}
		}
		if filter.allowsLoopback(addrString(addr)) {
			return routeResult{action: routeLoopback}
		}
		return routeResult{action: routeDrop, reason: "loopback not allowed"}
	}

	// IP allowlist: forward directly on any port.
	if filter.CheckIP != nil {
		if nip, ok := toNetIP(addr); ok && filter.CheckIP(nip) {
			return routeResult{action: routeForward}
		}
	}

	// Domain filtering active: route by port.
	if dnsFilter != nil {
		switch port {
		case dnsPort:
			return routeResult{action: routeDNS}
		case tlsPort:
			return routeResult{action: routeTLS}
		case httpPort:
			if filter.AllowHTTP {
				return routeResult{action: routeHTTP}
			}
			return routeResult{action: routeDrop, reason: "port 80 disabled"}
		default:
			return routeResult{action: routeDrop, reason: "port not allowed"}
		}
	}

	return routeResult{action: routeForward}
}

// setupTCPForwarding installs a TCP forwarder that proxies connections to the real network.
// Routing is determined by routeDecision: DNS, TLS, HTTP, loopback, forward, or drop.
func setupTCPForwarding(s *stack.Stack, filter *FilterConfig, dnsFilter *DNSFilter) {
	logger := filterLogger(filter)
	fwd := tcp.NewForwarder(s, 0, maxTCPInFlight, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst := net.JoinHostPort(addrString(id.LocalAddress), fmt.Sprintf("%d", id.LocalPort))
		result := routeDecision(id.LocalAddress, id.LocalPort, filter, dnsFilter)
		if result.action == routeDrop {
			logger.Event("tcp_connect", dst, "blocked", result.reason)
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

		local := gonet.NewTCPConn(&wq, ep)
		if logger.IsDebug() {
			logger.Debug("tcp accept: %s:%d → %s", addrString(id.RemoteAddress), id.RemotePort, dst)
		}

		switch result.action {
		case routeDNS:
			go dnsFilter.handleTCPQuery(local, dst)
		case routeTLS:
			go handleTLSConnection(local, dst, filter)
		case routeHTTP:
			go handleHTTPConnection(local, dst, filter)
		case routeLoopback:
			hostDst := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", id.LocalPort))
			go forwardTCP(local, hostDst, logger)
		default: // routeForward
			remote, dialErr := net.DialTimeout("tcp", dst, tcpDialTimeout)
			if dialErr != nil {
				logger.Warn("tcp forward %s: %v", dst, dialErr)
				_ = local.Close()
				return
			}
			go relay(local, remote, dst, logger)
		}
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
// Routing is determined by routeDecision: DNS, loopback, forward, or drop.
func setupUDPForwarding(s *stack.Stack, filter *FilterConfig, dnsFilter *DNSFilter) {
	logger := filterLogger(filter)
	fwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}

		dst := net.JoinHostPort(addrString(id.LocalAddress), fmt.Sprintf("%d", id.LocalPort))
		local := gonet.NewUDPConn(&wq, ep)
		result := routeDecision(id.LocalAddress, id.LocalPort, filter, dnsFilter)

		switch result.action {
		case routeDNS:
			go dnsFilter.handleQuery(local, dst)
		case routeLoopback:
			hostDst := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", id.LocalPort))
			remote, dialErr := net.Dial("udp", hostDst)
			if dialErr != nil {
				logger.Warn("localhost udp forward %s: %v", hostDst, dialErr)
				ep.Close()
				return true
			}
			go relayUDP(local, remote)
		case routeForward:
			remote, dialErr := net.Dial("udp", dst)
			if dialErr != nil {
				logger.Warn("udp forward %s: %v", dst, dialErr)
				ep.Close()
				return true
			}
			go relayUDP(local, remote)
		default: // routeDrop, routeTLS, routeHTTP
			logger.Debug("udp dropped: %s (%s)", dst, result.reason)
			_ = local.Close()
		}
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
