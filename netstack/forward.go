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
	udpMaxPacketSize   = 65535
	dnsMaxResponseSize = 4096 // EDNS0 max; avoids 64KB allocation per query.
)

// setupTCPForwarding installs a TCP forwarder that proxies connections to the real network.
func setupTCPForwarding(s *stack.Stack) {
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
		remote, dialErr := net.DialTimeout("tcp", dst, tcpDialTimeout)
		if dialErr != nil {
			fmt.Fprintf(os.Stderr, "curb: tcp forward %s: %v\n", dst, dialErr)
			ep.Close()
			return
		}

		local := gonet.NewTCPConn(&wq, ep)
		go relay(local, remote)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

// setupUDPForwarding installs a UDP forwarder that proxies packets to the real network.
// If dnsFilter is non-nil, UDP port 53 traffic is routed through the DNS filter.
func setupUDPForwarding(s *stack.Stack, dnsFilter *DNSFilter) {
	fwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}

		dst := net.JoinHostPort(addrString(id.LocalAddress), fmt.Sprintf("%d", id.LocalPort))
		local := gonet.NewUDPConn(&wq, ep)

		// Route DNS traffic through the filter when active.
		if dnsFilter != nil && id.LocalPort == dnsPort {
			go dnsFilter.handleQuery(local, dst)
			return true
		}

		remote, dialErr := net.Dial("udp", dst)
		if dialErr != nil {
			fmt.Fprintf(os.Stderr, "curb: udp forward %s: %v\n", dst, dialErr)
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
