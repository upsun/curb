package policy

import (
	"net/netip"
	"slices"
)

// IPMatcher checks IP addresses against an allowlist of addresses and CIDR prefixes.
type IPMatcher struct {
	addrs    []netip.Addr
	prefixes []netip.Prefix
}

// NewIPMatcher creates an IPMatcher from a list of IP address and CIDR strings.
// Invalid entries are silently skipped (use ValidateIPs first).
func NewIPMatcher(ips []string) *IPMatcher {
	m := &IPMatcher{}
	for _, s := range ips {
		if prefix, err := netip.ParsePrefix(s); err == nil {
			m.prefixes = append(m.prefixes, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			m.addrs = append(m.addrs, addr)
		}
	}
	return m
}

// Match reports whether addr is allowed by this matcher.
func (m *IPMatcher) Match(addr netip.Addr) bool {
	if slices.Contains(m.addrs, addr) {
		return true
	}
	for _, p := range m.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ContainsLoopback reports whether any entry covers a loopback address
// (127.0.0.0/8 or ::1).
func (m *IPMatcher) ContainsLoopback() bool {
	lo4 := netip.MustParseAddr("127.0.0.1")
	lo6 := netip.MustParseAddr("::1")
	lo4prefix := netip.MustParsePrefix("127.0.0.0/8")
	for _, a := range m.addrs {
		if a == lo4 || a == lo6 || lo4prefix.Contains(a) {
			return true
		}
	}
	for _, p := range m.prefixes {
		if p.Contains(lo4) || p.Contains(lo6) {
			return true
		}
	}
	return false
}
