package netstack

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// DNSFilter intercepts DNS queries and checks them against an allowlist.
type DNSFilter struct {
	// Check reports whether the given domain name is allowed.
	Check func(domain string) bool
	// Upstream overrides the DNS server address. Empty means transparent
	// forwarding to the original destination.
	Upstream string
}

// handleQuery reads a DNS query from the sandbox, checks it against the
// allowlist, and either forwards it or returns REFUSED.
func (f *DNSFilter) handleQuery(local *gonet.UDPConn, dst string) {
	buf := make([]byte, udpMaxPacketSize)
	for {
		_ = local.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, readErr := local.Read(buf)
		if n > 0 {
			resp := f.processPacket(buf[:n], dst)
			if resp != nil {
				if _, writeErr := local.Write(resp); writeErr != nil {
					break
				}
			}
		}
		if readErr != nil {
			break
		}
	}
	_ = local.Close()
}

// processPacket parses a DNS query, checks the allowlist, and returns
// either a REFUSED response or the upstream answer.
func (f *DNSFilter) processPacket(packet []byte, dst string) []byte {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		// Not a valid DNS query; drop silently.
		return nil
	}

	// Check all question names against the allowlist.
	for _, q := range msg.Question {
		if !f.Check(q.Name) {
			fmt.Fprintf(os.Stderr, "curb: dns blocked: %s\n", q.Name)
			return refused(&msg)
		}
	}

	// All questions allowed; forward to upstream.
	upstream := dst
	if f.Upstream != "" {
		upstream = f.Upstream
	}
	return f.forward(packet, upstream)
}

// forward sends the raw DNS query to the upstream server and returns the response.
func (f *DNSFilter) forward(packet []byte, upstream string) []byte {
	// Ensure the upstream has a port.
	_, _, err := net.SplitHostPort(upstream)
	if err != nil {
		upstream = net.JoinHostPort(upstream, "53")
	}

	conn, err := net.DialTimeout("udp", upstream, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns forward dial %s: %v\n", upstream, err)
		return nil
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(packet); err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns forward write: %v\n", err)
		return nil
	}

	buf := make([]byte, udpMaxPacketSize)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns forward read: %v\n", err)
		return nil
	}
	return buf[:n]
}

// refused constructs a DNS REFUSED response for the given query.
func refused(query *dns.Msg) []byte {
	resp := new(dns.Msg)
	resp.SetRcode(query, dns.RcodeRefused)
	out, err := resp.Pack()
	if err != nil {
		return nil
	}
	return out
}
