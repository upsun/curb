//go:build linux

package netstack

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestRouteDecision(t *testing.T) {
	allowAll := func(string) bool { return true }
	denyAll := func(string) bool { return false }
	minDNSFilter := &DNSFilter{Check: allowAll}

	tests := []struct {
		name       string
		addr       [4]byte
		port       uint16
		filter     *FilterConfig
		dnsFilter  *DNSFilter
		wantAction routeAction
		wantReason string
	}{
		{
			name:       "port 443 blocked",
			addr:       [4]byte{93, 184, 216, 34},
			port:       443,
			filter:     &FilterConfig{Check: allowAll},
			dnsFilter:  minDNSFilter,
			wantAction: routeDrop,
			wantReason: "port 443 blocked (use proxy)",
		},
		{
			name:       "allowed DNS",
			addr:       [4]byte{93, 184, 216, 34},
			port:       53,
			filter:     &FilterConfig{Check: allowAll},
			dnsFilter:  minDNSFilter,
			wantAction: routeDNS,
		},
		{
			name:       "allowed HTTP",
			addr:       [4]byte{93, 184, 216, 34},
			port:       80,
			filter:     &FilterConfig{Check: allowAll, AllowHTTP: true},
			dnsFilter:  minDNSFilter,
			wantAction: routeHTTP,
		},
		{
			name:       "HTTP disabled",
			addr:       [4]byte{93, 184, 216, 34},
			port:       80,
			filter:     &FilterConfig{Check: allowAll},
			dnsFilter:  minDNSFilter,
			wantAction: routeDrop,
			wantReason: "port 80 disabled",
		},
		{
			name:       "non-standard port 8080",
			addr:       [4]byte{93, 184, 216, 34},
			port:       8080,
			filter:     &FilterConfig{Check: allowAll},
			dnsFilter:  minDNSFilter,
			wantAction: routeDrop,
			wantReason: "port not allowed",
		},
		{
			name:       "non-standard port 4443",
			addr:       [4]byte{93, 184, 216, 34},
			port:       4443,
			filter:     &FilterConfig{Check: allowAll},
			dnsFilter:  minDNSFilter,
			wantAction: routeDrop,
			wantReason: "port not allowed",
		},
		{
			name:       "non-standard port 8443",
			addr:       [4]byte{93, 184, 216, 34},
			port:       8443,
			filter:     &FilterConfig{Check: allowAll},
			dnsFilter:  minDNSFilter,
			wantAction: routeDrop,
			wantReason: "port not allowed",
		},
		{
			name:       "loopback blocked",
			addr:       [4]byte{127, 0, 0, 1},
			port:       443,
			filter:     &FilterConfig{Check: allowAll},
			dnsFilter:  minDNSFilter,
			wantAction: routeDrop,
			wantReason: "loopback not allowed",
		},
		{
			name:       "loopback allowed",
			addr:       [4]byte{127, 0, 0, 1},
			port:       443,
			filter:     &FilterConfig{Check: allowAll, AllowLocalhost: true},
			dnsFilter:  minDNSFilter,
			wantAction: routeLoopback,
		},
		{
			name:       "loopback DNS always allowed",
			addr:       [4]byte{127, 0, 0, 1},
			port:       53,
			filter:     &FilterConfig{Check: allowAll},
			dnsFilter:  minDNSFilter,
			wantAction: routeDNS,
		},
		{
			name:       "loopback HTTP via checkIP",
			addr:       [4]byte{127, 0, 0, 1},
			port:       80,
			filter:     &FilterConfig{Check: allowAll, AllowHTTP: true, checkIP: func(string) bool { return true }},
			dnsFilter:  minDNSFilter,
			wantAction: routeLoopback,
		},
		{
			name:       "localhost-only mode rejects external",
			addr:       [4]byte{1, 2, 3, 4},
			port:       443,
			filter:     &FilterConfig{},
			wantAction: routeDrop,
			wantReason: "localhost-only mode",
		},
		{
			name:       "localhost-only mode allows loopback",
			addr:       [4]byte{127, 0, 0, 1},
			port:       80,
			filter:     &FilterConfig{},
			wantAction: routeLoopback,
		},
		{
			name:       "nil filter allows everything",
			wantAction: routeForward,
		},
		{
			name:       "nil filter with deny-all Check still allows (no dnsFilter)",
			addr:       [4]byte{93, 184, 216, 34},
			port:       443,
			filter:     &FilterConfig{Check: denyAll},
			wantAction: routeForward,
		},
		{
			name: "CheckIP allows any port",
			addr: [4]byte{10, 0, 0, 1},
			port: 8080,
			filter: &FilterConfig{
				CheckIP: func(addr netip.Addr) bool { return addr == netip.MustParseAddr("10.0.0.1") },
			},
			wantAction: routeForward,
		},
		{
			name: "CheckIP no match with deny-all Check rejects non-standard port",
			addr: [4]byte{10, 0, 0, 2},
			port: 8080,
			filter: &FilterConfig{
				Check:   denyAll,
				CheckIP: func(addr netip.Addr) bool { return addr == netip.MustParseAddr("10.0.0.1") },
			},
			dnsFilter:  minDNSFilter,
			wantAction: routeDrop,
			wantReason: "port not allowed",
		},
		{
			name: "CheckIP with domain Check allows IP on any port",
			addr: [4]byte{10, 0, 0, 1},
			port: 9999,
			filter: &FilterConfig{
				Check:   allowAll,
				CheckIP: func(addr netip.Addr) bool { return addr == netip.MustParseAddr("10.0.0.1") },
			},
			dnsFilter:  minDNSFilter,
			wantAction: routeForward,
		},
		{
			name: "CheckIP loopback allowed via CheckIP",
			addr: [4]byte{127, 0, 0, 1},
			port: 8080,
			filter: &FilterConfig{
				Check:   allowAll,
				CheckIP: func(addr netip.Addr) bool { return addr.IsLoopback() },
			},
			dnsFilter:  minDNSFilter,
			wantAction: routeLoopback,
		},
		{
			name: "CheckIP only mode allows loopback on any port",
			addr: [4]byte{127, 0, 0, 1},
			port: 3000,
			filter: &FilterConfig{
				CheckIP:        func(addr netip.Addr) bool { return addr.IsLoopback() },
				AllowLocalhost: true,
			},
			wantAction: routeLoopback,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := routeDecision(tcpip.AddrFrom4(tt.addr), tt.port, tt.filter, tt.dnsFilter)
			assert.Equal(t, tt.wantAction, got.action, "action")
			assert.Equal(t, tt.wantReason, got.reason, "reason")
		})
	}
}
