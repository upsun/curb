package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"
)

// ValidateDomains checks that each domain value is a plausible domain pattern.
// It rejects URLs, IP addresses, and values with invalid characters.
func ValidateDomains(domains []string) error {
	for _, d := range domains {
		if err := validateDomain(d); err != nil {
			return err
		}
	}
	return nil
}

func validateDomain(d string) error {
	if d == "*" || d == "localhost" {
		return nil
	}

	lower := strings.ToLower(d)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return fmt.Errorf("--domains %q looks like a URL; use the bare domain instead (e.g. %q)", d, stripScheme(d))
	}

	if _, err := netip.ParseAddr(d); err == nil {
		return fmt.Errorf("--domains %q is an IP address; use --ips instead", d)
	}
	if _, err := netip.ParsePrefix(d); err == nil {
		return fmt.Errorf("--domains %q is a CIDR range; use --ips instead", d)
	}

	for _, r := range d {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("--domains %q contains invalid character (whitespace or control)", d)
		}
		switch r {
		case '/', '\\', ':', '@', '#', '?':
			return fmt.Errorf("--domains %q contains invalid character %q", d, string(r))
		}
	}

	// Wildcard validation: only "*" (handled above) or "*.suffix".
	if strings.Contains(d, "*") {
		if !strings.HasPrefix(d, "*.") {
			return fmt.Errorf("--domains %q: wildcards must be * (match-all) or *.suffix", d)
		}
		suffix := d[2:]
		if suffix == "" {
			return fmt.Errorf("--domains %q: wildcard suffix must not be empty", d)
		}
	}

	return nil
}

// stripScheme removes http:// or https:// and any trailing path from a URL-like string.
func stripScheme(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ValidateIPs checks that each value is a valid IP address or CIDR prefix.
func ValidateIPs(ips []string) error {
	for _, s := range ips {
		if _, err := netip.ParsePrefix(s); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(s); err == nil {
			continue
		}
		return fmt.Errorf("--ips %q is not a valid IP address or CIDR range (e.g. 10.0.0.1, 192.168.0.0/16, ::1)", s)
	}
	return nil
}
