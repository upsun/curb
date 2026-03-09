package netstack

// FilterConfig holds the unified filtering configuration for the netstack.
// When non-nil with a non-nil Check function, traffic is filtered by port:
// DNS (53), TLS (443), HTTP (80 if AllowHTTP), and all other ports are dropped.
type FilterConfig struct {
	// Check reports whether the given domain name is allowed.
	Check func(domain string) bool
	// Upstream overrides the DNS server address. Empty means transparent
	// forwarding to the original destination.
	Upstream string
	// BlockECH blocks TLS connections that include Encrypted Client Hello.
	BlockECH bool
	// RequireSNI blocks TLS connections without a Server Name Indication extension.
	RequireSNI bool
	// AllowHTTP permits filtered plaintext HTTP on port 80.
	AllowHTTP bool
}
