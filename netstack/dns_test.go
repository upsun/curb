package netstack

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
