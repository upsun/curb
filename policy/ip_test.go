package policy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPMatcher_Match(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
		addr string
		want bool
	}{
		{"exact IPv4 match", []string{"10.0.0.1"}, "10.0.0.1", true},
		{"exact IPv4 no match", []string{"10.0.0.1"}, "10.0.0.2", false},
		{"exact IPv6 match", []string{"::1"}, "::1", true},
		{"exact IPv6 no match", []string{"::1"}, "::2", false},
		{"CIDR match", []string{"192.168.0.0/16"}, "192.168.1.100", true},
		{"CIDR no match", []string{"192.168.0.0/16"}, "10.0.0.1", false},
		{"mixed match via CIDR", []string{"10.0.0.1", "172.16.0.0/12"}, "172.20.5.3", true},
		{"mixed match via exact", []string{"10.0.0.1", "172.16.0.0/12"}, "10.0.0.1", true},
		{"mixed no match", []string{"10.0.0.1", "172.16.0.0/12"}, "8.8.8.8", false},
		{"IPv6 CIDR", []string{"fd00::/8"}, "fd12::1", true},
		{"empty matcher", nil, "10.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewIPMatcher(tt.ips)
			addr := netip.MustParseAddr(tt.addr)
			assert.Equal(t, tt.want, m.Match(addr))
		})
	}
}

func TestIPMatcher_ContainsLoopback(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
		want bool
	}{
		{"exact 127.0.0.1", []string{"127.0.0.1"}, true},
		{"exact ::1", []string{"::1"}, true},
		{"127.x range", []string{"127.0.0.50"}, true},
		{"CIDR covering 127.0.0.1", []string{"127.0.0.0/8"}, true},
		{"CIDR covering ::1", []string{"::0/0"}, true},
		{"no loopback", []string{"10.0.0.1", "192.168.0.0/16"}, false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewIPMatcher(tt.ips)
			assert.Equal(t, tt.want, m.ContainsLoopback())
		})
	}
}
