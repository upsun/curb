//go:build linux

package netstack

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/upsun/curb/clog"
)

// newTestLogger creates a quiet Logger for tests. It is closed automatically
// via t.Cleanup.
func newTestLogger(t *testing.T) *clog.Logger {
	t.Helper()
	l, err := clog.New("", false, false, false)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	return l
}

// startTCPDNSServer starts a TCP DNS server that responds to queries with a
// single A record pointing to responseIP. It returns the listener address.
func startTCPDNSServer(t *testing.T, responseIP string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				var length uint16
				if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
					return
				}
				buf := make([]byte, length)
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				var msg dns.Msg
				if err := msg.Unpack(buf); err != nil {
					return
				}
				resp := new(dns.Msg)
				resp.SetReply(&msg)
				resp.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP(responseIP),
					},
				}
				out, _ := resp.Pack()
				respLen := uint16(len(out))
				_ = binary.Write(conn, binary.BigEndian, respLen)
				_, _ = conn.Write(out)
			}()
		}
	}()

	return ln.Addr().String()
}

func TestRefused(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("blocked.example.com.", dns.TypeA)
	query.Id = 1234

	out := refused(query)
	require.NotNil(t, out)

	var resp dns.Msg
	require.NoError(t, resp.Unpack(out))
	assert.Equal(t, uint16(1234), resp.Id)
	assert.True(t, resp.Response)
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)
	assert.Len(t, resp.Question, 1)
	assert.Equal(t, "blocked.example.com.", resp.Question[0].Name)
}

func TestProcessPacket_Blocked(t *testing.T) {
	f := &DNSFilter{
		Check: func(domain string) bool { return false },
	}

	query := new(dns.Msg)
	query.SetQuestion("evil.com.", dns.TypeA)
	query.Id = 5678
	packed, err := query.Pack()
	require.NoError(t, err)

	result := f.processPacket(packed, "127.0.0.53:53")
	require.NotNil(t, result)

	var resp dns.Msg
	require.NoError(t, resp.Unpack(result))
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)
	assert.Equal(t, uint16(5678), resp.Id)
}

func TestProcessPacket_InvalidPacket(t *testing.T) {
	f := &DNSFilter{
		Check: func(domain string) bool { return true },
	}
	result := f.processPacket([]byte{0, 1, 2}, "127.0.0.53:53")
	assert.Nil(t, result)
}

func TestProcessPacket_MultipleQuestions(t *testing.T) {
	f := &DNSFilter{
		Check: func(domain string) bool {
			return domain == "allowed.com." || domain == "allowed.com"
		},
	}

	query := new(dns.Msg)
	query.Id = 9999
	query.Question = []dns.Question{
		{Name: "allowed.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "blocked.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	packed, err := query.Pack()
	require.NoError(t, err)

	result := f.processPacket(packed, "127.0.0.53:53")
	require.NotNil(t, result)

	var resp dns.Msg
	require.NoError(t, resp.Unpack(result))
	assert.Equal(t, dns.RcodeRefused, resp.Rcode, "any blocked question should REFUSE the entire query")
}

func TestCheckPacket_SubdomainExfiltration(t *testing.T) {
	f := &DNSFilter{
		Check: func(domain string) bool { return domain == "good.com." },
	}

	query := new(dns.Msg)
	query.SetQuestion("data.evil.com.", dns.TypeA)
	packed, err := query.Pack()
	require.NoError(t, err)

	resp, allowed := f.checkPacket(packed)
	assert.False(t, allowed)
	assert.NotNil(t, resp)

	var msg dns.Msg
	require.NoError(t, msg.Unpack(resp))
	assert.Equal(t, dns.RcodeRefused, msg.Rcode)
}

func TestCheckPacket_NoQuestions(t *testing.T) {
	f := &DNSFilter{
		Check: func(string) bool { return true },
	}

	query := new(dns.Msg)
	query.Id = 1111
	// No questions set.
	packed, err := query.Pack()
	require.NoError(t, err)

	resp, allowed := f.checkPacket(packed)
	assert.False(t, allowed)
	assert.Nil(t, resp, "no-questions packet should be dropped (nil response)")
}

func TestCheckPacket_CasePassthrough(t *testing.T) {
	var checkedName string
	f := &DNSFilter{
		Check: func(domain string) bool {
			checkedName = domain
			return true
		},
	}

	query := new(dns.Msg)
	query.SetQuestion("EVIL.COM.", dns.TypeA)
	packed, err := query.Pack()
	require.NoError(t, err)

	_, allowed := f.checkPacket(packed)
	assert.True(t, allowed)
	// The dns library preserves case from the wire format in Question[].Name.
	assert.Equal(t, "EVIL.COM.", checkedName, "raw QNAME case should be passed to Check")
}

// newStripFilter creates a DNSFilter with ECH stripping enabled for testing.
func newStripFilter() *DNSFilter {
	return &DNSFilter{Check: func(string) bool { return true }, stripECH: true}
}

func TestProcessECHStrip_HTTPS(t *testing.T) {
	f := newStripFilter()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeHTTPS)
	msg.Response = true
	msg.Answer = []dns.RR{
		&dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
					&dns.SVCBECHConfig{ECH: []byte("dummy-ech-config")},
					&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("1.2.3.4")}},
				},
			},
		},
	}
	packed, err := msg.Pack()
	require.NoError(t, err)

	result := f.processResponse(packed)

	var out dns.Msg
	require.NoError(t, out.Unpack(result))
	require.Len(t, out.Answer, 1)
	https, ok := out.Answer[0].(*dns.HTTPS)
	require.True(t, ok)
	for _, kv := range https.Value {
		assert.NotEqual(t, dns.SVCB_ECHCONFIG, kv.Key(), "ECH SvcParam should be stripped")
	}
	assert.Len(t, https.Value, 2, "should retain alpn and ipv4hint")
}

func TestProcessECHStrip_SVCB(t *testing.T) {
	f := newStripFilter()
	msg := new(dns.Msg)
	msg.SetQuestion("_dns.example.com.", dns.TypeSVCB)
	msg.Response = true
	msg.Answer = []dns.RR{
		&dns.SVCB{
			Hdr:      dns.RR_Header{Name: "_dns.example.com.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   ".",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBECHConfig{ECH: []byte("ech-data")},
			},
		},
	}
	packed, err := msg.Pack()
	require.NoError(t, err)

	result := f.processResponse(packed)

	var out dns.Msg
	require.NoError(t, out.Unpack(result))
	require.Len(t, out.Answer, 1)
	svcb, ok := out.Answer[0].(*dns.SVCB)
	require.True(t, ok)
	assert.Empty(t, svcb.Value, "ECH SvcParam should be stripped from SVCB")
}

func TestProcessECHStrip_NoECH(t *testing.T) {
	f := newStripFilter()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeHTTPS)
	msg.Response = true
	msg.Answer = []dns.RR{
		&dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBAlpn{Alpn: []string{"h2"}},
				},
			},
		},
	}
	packed, err := msg.Pack()
	require.NoError(t, err)

	result := f.processResponse(packed)
	assert.Equal(t, packed, result, "response without ECH should be returned unchanged")
}

func TestProcessECHStrip_InvalidDNS(t *testing.T) {
	f := newStripFilter()
	data := []byte{0x00, 0x01, 0x02}
	result := f.processResponse(data)
	assert.Equal(t, data, result, "invalid DNS should be returned unchanged")
}

func TestProcessECHStrip_Extra(t *testing.T) {
	f := newStripFilter()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeHTTPS)
	msg.Response = true
	msg.Extra = []dns.RR{
		&dns.HTTPS{
			SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value: []dns.SVCBKeyValue{
					&dns.SVCBECHConfig{ECH: []byte("ech-in-extra")},
				},
			},
		},
	}
	packed, err := msg.Pack()
	require.NoError(t, err)

	result := f.processResponse(packed)

	var out dns.Msg
	require.NoError(t, out.Unpack(result))
	require.Len(t, out.Extra, 1)
	https, ok := out.Extra[0].(*dns.HTTPS)
	require.True(t, ok)
	assert.Empty(t, https.Value, "ECH should be stripped from Extra section too")
}

func TestProcessECHStrip_CachesIPs(t *testing.T) {
	f := newStripFilter()

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34"),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120},
			AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
		},
	}
	packed, err := msg.Pack()
	require.NoError(t, err)

	f.processResponse(packed)

	assert.True(t, f.isResolvedIP("93.184.216.34"))
	assert.True(t, f.isResolvedIP("2606:2800:220:1:248:1893:25c8:1946"))
	assert.False(t, f.isResolvedIP("1.1.1.1"))
}

func TestIsResolvedIP_Expiry(t *testing.T) {
	f := &DNSFilter{Check: func(string) bool { return true }}
	// Store with an already-expired time.
	f.resolvedIPs.Store("10.0.0.1", time.Now().Add(-1*time.Second))

	assert.False(t, f.isResolvedIP("10.0.0.1"), "expired IP should not be resolved")

	// Confirm the entry was cleaned up.
	_, loaded := f.resolvedIPs.Load("10.0.0.1")
	assert.False(t, loaded, "expired entry should be deleted")
}

func TestProcessECHStrip_MinTTL(t *testing.T) {
	f := newStripFilter()

	msg := new(dns.Msg)
	msg.SetQuestion("short.com.", dns.TypeA)
	msg.Response = true
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "short.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
			A:   net.ParseIP("1.2.3.4"),
		},
	}
	packed, err := msg.Pack()
	require.NoError(t, err)

	f.processResponse(packed)

	// The entry should exist and not expire for at least minCacheTTL.
	val, ok := f.resolvedIPs.Load("1.2.3.4")
	require.True(t, ok)
	expiry := val.(time.Time)
	assert.True(t, expiry.After(time.Now().Add(50*time.Second)), "TTL=5 should be promoted to minCacheTTL")
}

// TestForwardDNS_UDP tests the DNS UDP forward path with a local UDP server.
func TestForwardDNS_UDP(t *testing.T) {
	// Start a local UDP DNS server that returns a fixed A record.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()

	go func() {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var msg dns.Msg
		if err := msg.Unpack(buf[:n]); err != nil {
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(&msg)
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("1.2.3.4"),
			},
		}
		out, _ := resp.Pack()
		_, _ = pc.WriteTo(out, addr)
	}()

	l := newTestLogger(t)

	f := &DNSFilter{
		Check:  func(string) bool { return true },
		Logger: l,
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	packed, err := query.Pack()
	require.NoError(t, err)

	resp := f.forward(packed, pc.LocalAddr().String())
	require.NotNil(t, resp)

	var msg dns.Msg
	require.NoError(t, msg.Unpack(resp))
	require.Len(t, msg.Answer, 1)
	a, ok := msg.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "1.2.3.4", a.A.String())
}

// TestForwardDNS_TCP tests the DNS TCP forward path with a local TCP server.
func TestForwardDNS_TCP(t *testing.T) {
	addr := startTCPDNSServer(t, "5.6.7.8")

	l := newTestLogger(t)

	f := &DNSFilter{
		Check:  func(string) bool { return true },
		Logger: l,
	}

	query := new(dns.Msg)
	query.SetQuestion("tcp.example.com.", dns.TypeA)
	packed, err := query.Pack()
	require.NoError(t, err)

	resp := f.forwardTCP(packed, addr)
	require.NotNil(t, resp)

	var msg dns.Msg
	require.NoError(t, msg.Unpack(resp))
	require.Len(t, msg.Answer, 1)
	a, ok := msg.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "5.6.7.8", a.A.String())
}

// TestHandleTCPQuery tests the full TCP DNS query handler.
func TestHandleTCPQuery(t *testing.T) {
	addr := startTCPDNSServer(t, "9.8.7.6")

	l := newTestLogger(t)

	f := &DNSFilter{
		Check:  func(string) bool { return true },
		Logger: l,
	}

	// Create a pipe to simulate the TCP connection from the sandbox.
	client, server := net.Pipe()

	go f.handleTCPQuery(server, addr)

	// Send a DNS query over TCP.
	query := new(dns.Msg)
	query.SetQuestion("tcp-handler.example.com.", dns.TypeA)
	packed, err := query.Pack()
	require.NoError(t, err)

	qLen := uint16(len(packed))
	require.NoError(t, binary.Write(client, binary.BigEndian, qLen))
	_, err = client.Write(packed)
	require.NoError(t, err)

	// Read the response.
	var respLen uint16
	require.NoError(t, binary.Read(client, binary.BigEndian, &respLen))
	respBuf := make([]byte, respLen)
	_, err = io.ReadFull(client, respBuf)
	require.NoError(t, err)

	var resp dns.Msg
	require.NoError(t, resp.Unpack(respBuf))
	require.Len(t, resp.Answer, 1)
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "9.8.7.6", a.A.String())

	_ = client.Close()
}

// TestHandleTCPQuery_Blocked tests that blocked queries return REFUSED over TCP.
func TestHandleTCPQuery_Blocked(t *testing.T) {
	l := newTestLogger(t)

	f := &DNSFilter{
		Check:  func(string) bool { return false },
		Logger: l,
	}

	client, server := net.Pipe()

	go f.handleTCPQuery(server, "127.0.0.53:53")

	query := new(dns.Msg)
	query.SetQuestion("blocked.com.", dns.TypeA)
	packed, err := query.Pack()
	require.NoError(t, err)

	qLen := uint16(len(packed))
	require.NoError(t, binary.Write(client, binary.BigEndian, qLen))
	_, err = client.Write(packed)
	require.NoError(t, err)

	var respLen uint16
	require.NoError(t, binary.Read(client, binary.BigEndian, &respLen))
	respBuf := make([]byte, respLen)
	_, err = io.ReadFull(client, respBuf)
	require.NoError(t, err)

	var resp dns.Msg
	require.NoError(t, resp.Unpack(respBuf))
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)

	_ = client.Close()
}

// TestCheckPacket_SeenBlockedDedup tests that duplicate blocked domains are only logged once.
func TestCheckPacket_SeenBlockedDedup(t *testing.T) {
	l := newTestLogger(t)

	f := &DNSFilter{
		Check:  func(string) bool { return false },
		Logger: l,
	}

	query := new(dns.Msg)
	query.SetQuestion("repeat.com.", dns.TypeA)
	packed, err := query.Pack()
	require.NoError(t, err)

	// First call should store in seenBlocked.
	resp1, allowed1 := f.checkPacket(packed)
	assert.False(t, allowed1)
	assert.NotNil(t, resp1)

	// Second call should still block but not re-store (dedup).
	resp2, allowed2 := f.checkPacket(packed)
	assert.False(t, allowed2)
	assert.NotNil(t, resp2)

	// Verify it was stored.
	_, loaded := f.seenBlocked.Load("repeat.com.")
	assert.True(t, loaded)
}
