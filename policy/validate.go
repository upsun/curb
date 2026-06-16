package policy

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
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
	return validateDomainPattern(d, "--domains")
}

// validateDomainPattern checks that d is a plausible domain pattern, attributing
// any error to subject (a flag or context name) so the message matches how the
// value was supplied — `--domains` for the flag, `injection host` for a
// credential-injection target.
func validateDomainPattern(d, subject string) error {
	if d == "*" || d == "localhost" {
		return nil
	}

	lower := strings.ToLower(d)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return fmt.Errorf("%s %q looks like a URL; use the bare domain instead (e.g. %q)", subject, d, stripScheme(d))
	}

	if _, err := netip.ParseAddr(d); err == nil {
		return fmt.Errorf("%s %q is an IP address; use --ips instead", subject, d)
	}
	if _, err := netip.ParsePrefix(d); err == nil {
		return fmt.Errorf("%s %q is a CIDR range; use --ips instead", subject, d)
	}

	for _, r := range d {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("%s %q contains invalid character (whitespace or control)", subject, d)
		}
		switch r {
		case '/', '\\', ':', '@', '#', '?', '=':
			return fmt.Errorf("%s %q contains invalid character %q", subject, d, string(r))
		}
	}

	// Wildcard validation: only "*" (handled above) or "*.suffix".
	if strings.Contains(d, "*") {
		if !strings.HasPrefix(d, "*.") {
			return fmt.Errorf("%s %q: wildcards must be * (match-all) or *.suffix", subject, d)
		}
		suffix := d[2:]
		if suffix == "" {
			return fmt.Errorf("%s %q: wildcard suffix must not be empty", subject, d)
		}
	}

	return nil
}

// InjectTarget is one destination a credential is bound to: a hostname or IP
// literal plus the TLS port (default 443). The proxy injects the credential
// only for a connection matching both Host and Port, so the credential's
// destination is exact.
type InjectTarget struct {
	Host string // normalized hostname, or canonical IP literal
	Port string // numeric port, "443" by default
	IsIP bool   // Host is an IP literal (authorized via --ips, not --domains)
}

// ParseInjectHeader parses one credential-injection binding
// "ENV_VAR:TARGET[,TARGET...]", where each TARGET is HOST[:PORT] and HOST is a
// hostname or IP literal (PORT defaults to 443). The binding is var-first
// because a credential belongs to its variable and may be valid for more than
// one destination. Splitting on the first ":" is unambiguous because an env var
// name can never contain one. Callers wrap the error with their own prefix.
func ParseInjectHeader(entry string) (envVar string, targets []InjectTarget, err error) {
	envVar, rest, ok := strings.Cut(entry, ":")
	if !ok || envVar == "" || rest == "" {
		return "", nil, fmt.Errorf("must be ENV_VAR:HOST[,HOST...], got %q", entry)
	}
	if !ValidEnvName(envVar) {
		return "", nil, fmt.Errorf("%q is not a valid environment variable name", envVar)
	}
	for item := range strings.SplitSeq(rest, ",") {
		t, err := parseInjectTarget(item)
		if err != nil {
			return "", nil, err
		}
		targets = append(targets, t)
	}
	return envVar, targets, nil
}

// parseInjectTarget parses one HOST[:PORT] target. HOST is a hostname or IP
// literal; PORT defaults to 443. An IPv6 literal must be bracketed when a port
// is present (net.SplitHostPort semantics); a bare IPv6 literal needs no
// brackets. Unlike a --domains pattern, an injection host must be exact: a
// wildcard cannot identify the single destination a credential belongs to.
func parseInjectTarget(item string) (InjectTarget, error) {
	if item == "" {
		return InjectTarget{}, fmt.Errorf("empty injection target")
	}
	// A bare IP literal (no port): ParseAddr accepts an unbracketed IPv6
	// address, which SplitHostPort below would reject.
	if addr, err := netip.ParseAddr(item); err == nil {
		return InjectTarget{Host: addr.String(), Port: "443", IsIP: true}, nil
	}
	host, port := item, "443"
	if h, p, ok := splitInjectPort(item); ok {
		if err := validatePort(p); err != nil {
			return InjectTarget{}, fmt.Errorf("injection target %q: %w", item, err)
		}
		host, port = h, p
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return InjectTarget{Host: addr.String(), Port: port, IsIP: true}, nil
	}
	if strings.Contains(host, "*") {
		return InjectTarget{}, fmt.Errorf("injection host %q must be an exact hostname (no wildcards)", host)
	}
	if err := validateDomainPattern(host, "injection host"); err != nil {
		return InjectTarget{}, err
	}
	return InjectTarget{Host: NormalizeHost(host), Port: port, IsIP: false}, nil
}

// splitInjectPort separates a custom port from a target, returning ok=false
// when none is present so the default applies. A bracketed IPv6 literal uses
// net.SplitHostPort; otherwise a port is the run of digits after a final colon,
// so "https://x" or "host:bad" fall through to host validation (which gives a
// clearer error than a bogus port would).
func splitInjectPort(item string) (host, port string, ok bool) {
	if strings.HasPrefix(item, "[") {
		h, p, err := net.SplitHostPort(item)
		if err != nil {
			return "", "", false
		}
		return h, p, true
	}
	i := strings.LastIndexByte(item, ':')
	if i < 0 || !isAllDigits(item[i+1:]) {
		return "", "", false
	}
	return item[:i], item[i+1:], true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// validatePort checks that p is a numeric TCP port in 1..65535.
func validatePort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q (want 1-65535)", p)
	}
	return nil
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
