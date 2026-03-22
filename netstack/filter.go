//go:build linux

package netstack

import (
	"net/netip"

	"github.com/upsun/curb/clog"
)

// FilterConfig holds the unified filtering configuration for the netstack.
// When non-nil with a non-nil Check function, traffic is filtered by port:
// DNS (53), HTTP (80 if AllowHTTP). Port 443 is dropped (use the MITM proxy
// for HTTPS). All other ports are also dropped.
type FilterConfig struct {
	// Check reports whether the given domain name is allowed.
	Check func(domain string) bool
	// AllowHTTP permits filtered plaintext HTTP on port 80.
	AllowHTTP bool
	// CheckIP reports whether a direct connection to the given IP is allowed.
	// Set from --ips allowlist. Connections matching CheckIP bypass port restrictions.
	CheckIP func(addr netip.Addr) bool
	// AllowLocalhost forwards connections to 127.0.0.0/8 to the host.
	AllowLocalhost bool
	// Logger for filtering events.
	Logger *clog.Logger

	// checkIP reports whether the given IP was resolved for an allowed domain.
	// Set internally by newDNSFilter.
	checkIP func(ip string) bool
}

// allowsLoopback reports whether a connection to the given loopback IP
// should be forwarded. True if AllowLocalhost is set explicitly, or if
// the IP was resolved from an allowed domain via DNS.
func (f *FilterConfig) allowsLoopback(ip string) bool {
	if f == nil {
		return false
	}
	if f.AllowLocalhost {
		return true
	}
	if f.CheckIP != nil {
		if addr, err := netip.ParseAddr(ip); err == nil && f.CheckIP(addr) {
			return true
		}
	}
	return f.checkIP != nil && f.checkIP(ip)
}
