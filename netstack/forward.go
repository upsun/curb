package netstack

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

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
// filtering is not active.
func newDNSFilter(filter *FilterConfig) *DNSFilter {
	if filter == nil || filter.Check == nil {
		return nil
	}
	return &DNSFilter{Check: filter.Check, Upstream: filter.Upstream, Logger: filter.Logger}
}

// isLoopback reports whether the address is in 127.0.0.0/8.
func isLoopback(addr tcpip.Address) bool {
	b := addr.As4()
	return b[0] == 127
}

// setupTCPForwarding installs a TCP forwarder that proxies connections to the real network.
// If filter is active, traffic is routed by port:
// 53 → DNS filter, 443 → TLS SNI filter, 80 → HTTP filter (if AllowHTTP), others → drop.
// Loopback destinations (127.0.0.0/8) are forwarded to the host if AllowLocalhost is set.
func setupTCPForwarding(s *stack.Stack, filter *FilterConfig, dnsFilter *DNSFilter) {
	fwd := tcp.NewForwarder(s, 0, maxTCPInFlight, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)

		dst := net.JoinHostPort(addrString(id.LocalAddress), fmt.Sprintf("%d", id.LocalPort))
		local := gonet.NewTCPConn(&wq, ep)

		// Loopback traffic: DNS always forwarded, other ports need AllowLocalhost.
		if isLoopback(id.LocalAddress) {
			if id.LocalPort == dnsPort && dnsFilter != nil {
				go dnsFilter.handleTCPQuery(local, dst)
				return
			}
			if filter != nil && filter.AllowLocalhost {
				// Rewrite destination to 127.0.0.1:<port> on the host.
				hostDst := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", id.LocalPort))
				go forwardTCP(local, hostDst)
				return
			}
			_ = local.Close()
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
				if filter.AllowHTTP {
					go handleHTTPConnection(local, dst, filter)
				} else {
					filter.Logger.Event("http_request", dst, "blocked", "port_80_disabled")
					_ = local.Close()
				}
			default:
				_ = local.Close()
			}
			return
		}

		remote, dialErr := net.DialTimeout("tcp", dst, tcpDialTimeout)
		if dialErr != nil {
			fmt.Fprintf(os.Stderr, "curb: error: tcp forward %s: %v\n", dst, dialErr)
			_ = local.Close()
			return
		}

		go relay(local, remote)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

// forwardTCP dials the destination and relays data bidirectionally.
func forwardTCP(local net.Conn, dst string) {
	remote, err := net.DialTimeout("tcp", dst, tcpDialTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "curb: error: localhost forward %s: %v\n", dst, err)
		_ = local.Close()
		return
	}
	relay(local, remote)
}

// setupUDPForwarding installs a UDP forwarder that proxies packets to the real network.
// If dnsFilter is non-nil, only UDP port 53 (DNS) is forwarded; all other UDP is dropped.
// Loopback DNS is always forwarded; other loopback UDP requires AllowLocalhost.
func setupUDPForwarding(s *stack.Stack, filter *FilterConfig, dnsFilter *DNSFilter) {
	fwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}

		dst := net.JoinHostPort(addrString(id.LocalAddress), fmt.Sprintf("%d", id.LocalPort))
		local := gonet.NewUDPConn(&wq, ep)

		// Loopback traffic: DNS always forwarded, other ports need AllowLocalhost.
		if isLoopback(id.LocalAddress) {
			if id.LocalPort == dnsPort && dnsFilter != nil {
				go dnsFilter.handleQuery(local, dst)
				return true
			}
			if filter != nil && filter.AllowLocalhost {
				hostDst := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", id.LocalPort))
				remote, dialErr := net.Dial("udp", hostDst)
				if dialErr != nil {
					fmt.Fprintf(os.Stderr, "curb: error: localhost udp forward %s: %v\n", hostDst, dialErr)
					ep.Close()
					return true
				}
				go relayUDP(local, remote)
				return true
			}
			_ = local.Close()
			return true
		}

		// When filtering is active, only DNS is allowed.
		if dnsFilter != nil {
			if id.LocalPort == dnsPort {
				go dnsFilter.handleQuery(local, dst)
			} else {
				_ = local.Close()
			}
			return true
		}

		remote, dialErr := net.Dial("udp", dst)
		if dialErr != nil {
			fmt.Fprintf(os.Stderr, "curb: error: udp forward %s: %v\n", dst, dialErr)
			ep.Close()
			return true
		}

		go relayUDP(local, remote)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
}

// relay copies data bidirectionally between two connections, then closes both.
func relay(a, b net.Conn) {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(a, b)
		close(done)
	}()
	_, _ = io.Copy(b, a)
	<-done
	_ = a.Close()
	_ = b.Close()
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
