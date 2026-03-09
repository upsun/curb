package netstack

import (
	"encoding/binary"
	"fmt"
	"io"
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

// checkPacket parses a DNS query and checks the allowlist.
// It returns the parsed message and true if all questions are allowed,
// or the REFUSED response bytes and false if any question is blocked.
// If the packet is not valid DNS, it returns nil and false.
func (f *DNSFilter) checkPacket(packet []byte) (refusedResp []byte, allowed bool) {
	var msg dns.Msg
	if err := msg.Unpack(packet); err != nil {
		// Not a valid DNS query; drop silently.
		return nil, false
	}

	// Check all question names against the allowlist.
	for _, q := range msg.Question {
		if !f.Check(q.Name) {
			fmt.Fprintf(os.Stderr, "curb: dns blocked: %s\n", q.Name)
			return refused(&msg), false
		}
	}
	return nil, true
}

// processPacket parses a DNS query, checks the allowlist, and returns
// either a REFUSED response or the upstream answer (via UDP).
func (f *DNSFilter) processPacket(packet []byte, dst string) []byte {
	resp, allowed := f.checkPacket(packet)
	if !allowed {
		return resp
	}

	// All questions allowed; forward to upstream via UDP.
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
		upstream = net.JoinHostPort(upstream, fmt.Sprintf("%d", dnsPort))
	}

	conn, err := net.DialTimeout("udp", upstream, dnsForwardTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns forward dial %s: %v\n", upstream, err)
		return nil
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(dnsForwardTimeout))
	if _, err := conn.Write(packet); err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns forward write: %v\n", err)
		return nil
	}

	buf := make([]byte, dnsMaxResponseSize)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns forward read: %v\n", err)
		return nil
	}
	return buf[:n]
}

// handleTCPQuery reads DNS queries from a TCP connection (RFC 1035 section 4.2.2:
// each message is prefixed with a 2-byte length), checks them against the
// allowlist, and either forwards them or returns REFUSED.
func (f *DNSFilter) handleTCPQuery(local net.Conn, dst string) {
	defer func() { _ = local.Close() }()

	for {
		_ = local.SetReadDeadline(time.Now().Add(udpIdleTimeout))

		// Read 2-byte length prefix.
		var length uint16
		if err := binary.Read(local, binary.BigEndian, &length); err != nil {
			break
		}
		if length == 0 || length > udpMaxPacketSize {
			break
		}

		// Read the DNS message.
		packet := make([]byte, length)
		if _, err := io.ReadFull(local, packet); err != nil {
			break
		}

		refusedResp, allowed := f.checkPacket(packet)
		var resp []byte
		if allowed {
			upstream := dst
			if f.Upstream != "" {
				upstream = f.Upstream
			}
			resp = f.forwardTCP(packet, upstream)
		} else {
			resp = refusedResp
		}
		if resp == nil {
			break
		}

		// Write 2-byte length prefix + response.
		respLen := uint16(len(resp))
		if err := binary.Write(local, binary.BigEndian, respLen); err != nil {
			break
		}
		if _, err := local.Write(resp); err != nil {
			break
		}
	}
}

// forwardTCP sends the raw DNS query to the upstream server via TCP and returns the response.
func (f *DNSFilter) forwardTCP(packet []byte, upstream string) []byte {
	// Ensure the upstream has a port.
	_, _, err := net.SplitHostPort(upstream)
	if err != nil {
		upstream = net.JoinHostPort(upstream, fmt.Sprintf("%d", dnsPort))
	}

	conn, err := net.DialTimeout("tcp", upstream, dnsForwardTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns tcp forward dial %s: %v\n", upstream, err)
		return nil
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(dnsForwardTimeout))

	// Write 2-byte length prefix + query.
	length := uint16(len(packet))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns tcp forward write length: %v\n", err)
		return nil
	}
	if _, err := conn.Write(packet); err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns tcp forward write: %v\n", err)
		return nil
	}

	// Read 2-byte length prefix.
	var respLen uint16
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns tcp forward read length: %v\n", err)
		return nil
	}
	if respLen == 0 || respLen > udpMaxPacketSize {
		return nil
	}

	buf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		fmt.Fprintf(os.Stderr, "curb: dns tcp forward read: %v\n", err)
		return nil
	}
	return buf
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
