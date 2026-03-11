package netstack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestRejectReason(t *testing.T) {
	allowAll := func(string) bool { return true }
	denyAll := func(string) bool { return false }
	minDNSFilter := &DNSFilter{Check: allowAll}

	tests := []struct {
		name      string
		addr      [4]byte
		port      uint16
		filter    *FilterConfig
		dnsFilter *DNSFilter
		want      string
	}{
		{
			name:      "allowed TLS",
			addr:      [4]byte{93, 184, 216, 34},
			port:      443,
			filter:    &FilterConfig{Check: allowAll},
			dnsFilter: minDNSFilter,
		},
		{
			name:      "allowed DNS",
			addr:      [4]byte{93, 184, 216, 34},
			port:      53,
			filter:    &FilterConfig{Check: allowAll},
			dnsFilter: minDNSFilter,
		},
		{
			name:      "allowed HTTP",
			addr:      [4]byte{93, 184, 216, 34},
			port:      80,
			filter:    &FilterConfig{Check: allowAll, AllowHTTP: true},
			dnsFilter: minDNSFilter,
		},
		{
			name:      "HTTP disabled",
			addr:      [4]byte{93, 184, 216, 34},
			port:      80,
			filter:    &FilterConfig{Check: allowAll},
			dnsFilter: minDNSFilter,
			want:      "port 80 disabled",
		},
		{
			name:      "non-standard port 8080",
			addr:      [4]byte{93, 184, 216, 34},
			port:      8080,
			filter:    &FilterConfig{Check: allowAll},
			dnsFilter: minDNSFilter,
			want:      "port not allowed",
		},
		{
			name:      "non-standard port 4443",
			addr:      [4]byte{93, 184, 216, 34},
			port:      4443,
			filter:    &FilterConfig{Check: allowAll},
			dnsFilter: minDNSFilter,
			want:      "port not allowed",
		},
		{
			name:      "non-standard port 8443",
			addr:      [4]byte{93, 184, 216, 34},
			port:      8443,
			filter:    &FilterConfig{Check: allowAll},
			dnsFilter: minDNSFilter,
			want:      "port not allowed",
		},
		{
			name:      "loopback blocked",
			addr:      [4]byte{127, 0, 0, 1},
			port:      443,
			filter:    &FilterConfig{Check: allowAll},
			dnsFilter: minDNSFilter,
			want:      "loopback not allowed",
		},
		{
			name:      "loopback allowed",
			addr:      [4]byte{127, 0, 0, 1},
			port:      443,
			filter:    &FilterConfig{Check: allowAll, AllowLocalhost: true},
			dnsFilter: minDNSFilter,
		},
		{
			name:      "loopback DNS always allowed",
			addr:      [4]byte{127, 0, 0, 1},
			port:      53,
			filter:    &FilterConfig{Check: allowAll},
			dnsFilter: minDNSFilter,
		},
		{
			name:      "loopback HTTP via checkIP",
			addr:      [4]byte{127, 0, 0, 1},
			port:      80,
			filter:    &FilterConfig{Check: allowAll, AllowHTTP: true, checkIP: func(string) bool { return true }},
			dnsFilter: minDNSFilter,
		},
		{
			name:   "localhost-only mode rejects external",
			addr:   [4]byte{1, 2, 3, 4},
			port:   443,
			filter: &FilterConfig{},
			want:   "localhost-only mode",
		},
		{
			name:   "localhost-only mode allows loopback",
			addr:   [4]byte{127, 0, 0, 1},
			port:   80,
			filter: &FilterConfig{},
		},
		{
			name: "nil filter allows everything",
		},
		{
			name:   "nil filter with deny-all Check still allows (no dnsFilter)",
			addr:   [4]byte{93, 184, 216, 34},
			port:   443,
			filter: &FilterConfig{Check: denyAll},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := stack.TransportEndpointID{
				LocalAddress: tcpip.AddrFrom4(tt.addr),
				LocalPort:    tt.port,
			}
			got := rejectReason(id, tt.filter, tt.dnsFilter)
			assert.Equal(t, tt.want, got)
		})
	}
}
