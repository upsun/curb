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
		case '/', '\\', ':', '@', '#', '?', '=':
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

// ValidateInjectHost validates a credential-injection host and returns it
// normalized (lowercase, no trailing dot). Unlike a --domains pattern, an
// injection host must be an exact hostname: a wildcard cannot identify the
// single destination a credential belongs to, and "*" would broaden the
// allowlist to every domain while never matching a binding at runtime.
func ValidateInjectHost(host string) (string, error) {
	if err := validateDomain(host); err != nil {
		return "", err
	}
	if strings.Contains(host, "*") {
		return "", fmt.Errorf("host %q must be an exact hostname (no wildcards)", host)
	}
	return NormalizeHost(host), nil
}

// ParseInjectHeader parses one credential-injection binding "ENV_VAR=HOST",
// returning the env var name and the normalized host. The binding is var-first
// because a credential belongs to its variable and may be valid for more than
// one host. Callers wrap the error with their own flag/field prefix.
func ParseInjectHeader(entry string) (envVar, host string, err error) {
	envVar, host, ok := strings.Cut(entry, "=")
	if !ok || envVar == "" || host == "" {
		return "", "", fmt.Errorf("must be ENV_VAR=HOST, got %q", entry)
	}
	if !ValidEnvName(envVar) {
		return "", "", fmt.Errorf("%q is not a valid environment variable name", envVar)
	}
	host, err = ValidateInjectHost(host)
	if err != nil {
		return "", "", err
	}
	return envVar, host, nil
}

// ValidEnvName reports whether name is a valid environment variable name (a C
// identifier: a letter or underscore, then letters, digits, or underscores).
// Credential-injection sources name the carrier var this way, so a typo is
// caught at parse time instead of silently matching nothing.
func ValidEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
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
