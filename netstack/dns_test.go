package netstack

import (
	"testing"

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
