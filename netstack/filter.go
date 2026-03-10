package netstack

import "github.com/upsun/curb/clog"

// ECH handling modes for FilterConfig.ECHMode.
const (
	ECHStrip = "strip" // Strip ECH config from DNS; allow residual ECH via DNS IP cache.
	ECHAllow = "allow" // Allow ECH unconditionally.
	ECHDeny  = "deny"  // Block ECH connections entirely.
)

// FilterConfig holds the unified filtering configuration for the netstack.
// When non-nil with a non-nil Check function, traffic is filtered by port:
// DNS (53), TLS (443), HTTP (80 if AllowHTTP), and all other ports are dropped.
type FilterConfig struct {
	// Check reports whether the given domain name is allowed.
	Check func(domain string) bool
	// ECHMode controls TLS Encrypted Client Hello handling (ECHStrip, ECHAllow, ECHDeny).
	ECHMode string
	// RequireSNI blocks TLS connections without a Server Name Indication extension.
	RequireSNI bool
	// AllowHTTP permits filtered plaintext HTTP on port 80.
	AllowHTTP bool
	// AllowLocalhost forwards connections to 127.0.0.0/8 to the host.
	AllowLocalhost bool
	// Logger for filtering events.
	Logger *clog.Logger

	// checkIP reports whether the given IP was resolved for an allowed domain.
	// Set internally by newDNSFilter when ECHMode is ECHStrip.
	checkIP func(ip string) bool
}
