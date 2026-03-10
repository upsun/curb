package netstack

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/upsun/curb/clog"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	// minCacheTTL is the minimum TTL for DNS IP cache entries.
	minCacheTTL = 60 * time.Second
)

// DNSFilter intercepts DNS queries and checks them against an allowlist.
type DNSFilter struct {
	// Check reports whether the given domain name is allowed.
	Check func(domain string) bool
	// Logger for DNS events.
	Logger *clog.Logger
	// stripECH removes ECH SvcParams from HTTPS/SVCB DNS responses.
	stripECH bool
	// seenBlocked tracks domains already logged as blocked to avoid repetition.
	seenBlocked sync.Map
	// resolvedIPs maps IP string to expiry time for the DNS IP cache.
	resolvedIPs sync.Map
}

// isResolvedIP reports whether the given IP was recently resolved via DNS.
func (f *DNSFilter) isResolvedIP(ip string) bool {
	val, ok := f.resolvedIPs.Load(ip)
	if !ok {
		return false
	}
	expiry := val.(time.Time)
	if time.Now().After(expiry) {
		f.resolvedIPs.Delete(ip)
		return false
	}
	return true
}

// processECHStrip parses a DNS response, caches A/AAAA IPs,
// and strips ECH SvcParams from HTTPS/SVCB records. It returns the
// (possibly modified) response. This single-parse approach avoids
// unpacking the DNS message twice.
func (f *DNSFilter) processECHStrip(response []byte) []byte {
	var msg dns.Msg
	if err := msg.Unpack(response); err != nil {
		return response
	}

	// Cache A/AAAA IPs for residual ECH validation.
	for _, rr := range msg.Answer {
		var ip string
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A.String()
		case *dns.AAAA:
			ip = r.AAAA.String()
		default:
			continue
		}
		ttl := max(time.Duration(rr.Header().Ttl)*time.Second, minCacheTTL)
		f.resolvedIPs.Store(ip, time.Now().Add(ttl))
	}

	// Strip ECH SvcParams from HTTPS/SVCB records.
	modified := false
	stripRRs := func(rrs []dns.RR) {
		for _, rr := range rrs {
			var svcb *dns.SVCB
			switch r := rr.(type) {
			case *dns.SVCB:
				svcb = r
			case *dns.HTTPS:
				svcb = &r.SVCB
			default:
				continue
			}
			filtered := svcb.Value[:0]
			for _, kv := range svcb.Value {
				if kv.Key() == dns.SVCB_ECHCONFIG {
					modified = true
					continue
				}
				filtered = append(filtered, kv)
			}
			svcb.Value = filtered
		}
	}
	stripRRs(msg.Answer)
	stripRRs(msg.Extra)

	if !modified {
		return response
	}
	out, err := msg.Pack()
	if err != nil {
		return response
	}
	return out
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

	// Drop packets with no questions (potential information leak).
	if len(msg.Question) == 0 {
		return nil, false
	}

	// Check all question names against the allowlist.
	for _, q := range msg.Question {
		if !f.Check(q.Name) {
			if _, dup := f.seenBlocked.LoadOrStore(q.Name, true); !dup {
				f.Logger.Event("dns_query", q.Name, "blocked", "domain")
			}
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

	// All questions allowed; forward to the original destination via UDP.
	resp = f.forward(packet, dst)
	if resp != nil && f.stripECH {
		resp = f.processECHStrip(resp)
	}
	return resp
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
		f.Logger.Warn("dns forward dial %s: %v", upstream, err)
		return nil
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(dnsForwardTimeout))
	if _, err := conn.Write(packet); err != nil {
		f.Logger.Warn("dns forward write: %v", err)
		return nil
	}

	buf := make([]byte, dnsMaxResponseSize)
	n, err := conn.Read(buf)
	if err != nil {
		f.Logger.Warn("dns forward read: %v", err)
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
			resp = f.forwardTCP(packet, dst)
			if resp != nil && f.stripECH {
				resp = f.processECHStrip(resp)
			}
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
		f.Logger.Warn("dns tcp forward dial %s: %v", upstream, err)
		return nil
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(dnsForwardTimeout))

	// Write 2-byte length prefix + query.
	length := uint16(len(packet))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		f.Logger.Warn("dns tcp forward write length: %v", err)
		return nil
	}
	if _, err := conn.Write(packet); err != nil {
		f.Logger.Warn("dns tcp forward write: %v", err)
		return nil
	}

	// Read 2-byte length prefix.
	var respLen uint16
	if err := binary.Read(conn, binary.BigEndian, &respLen); err != nil {
		f.Logger.Warn("dns tcp forward read length: %v", err)
		return nil
	}
	if respLen == 0 || respLen > udpMaxPacketSize {
		return nil
	}

	buf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		f.Logger.Warn("dns tcp forward read: %v", err)
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
