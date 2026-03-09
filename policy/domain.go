package policy

import "strings"

// DomainMatcher checks domain names against an allowlist with exact, wildcard,
// and subdomain matching support.
type DomainMatcher struct {
	exactDomains     map[string]bool
	wildcardSuffixes []string
	exactOnly        bool
	matchAll         bool
}

// NewDomainMatcher creates a matcher from a list of domain patterns.
// Patterns can be exact ("example.com"), wildcard ("*.github.com"), or "*" (match all).
// Unless exactOnly is true, "example.com" also matches "sub.example.com".
func NewDomainMatcher(domains []string, exactOnly bool) *DomainMatcher {
	m := &DomainMatcher{
		exactDomains: make(map[string]bool),
		exactOnly:    exactOnly,
	}
	for _, d := range domains {
		d = normalizeDomain(d)
		if d == "*" {
			m.matchAll = true
			return m
		}
		if strings.HasPrefix(d, "*.") {
			// *.github.com → ".github.com"
			m.wildcardSuffixes = append(m.wildcardSuffixes, d[1:])
		} else {
			m.exactDomains[d] = true
		}
	}
	return m
}

// Match reports whether domain is allowed by this matcher.
func (m *DomainMatcher) Match(domain string) bool {
	if m.matchAll {
		return true
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return false
	}

	// Exact match.
	if m.exactDomains[domain] {
		return true
	}

	// Subdomain of an exact domain (unless exactOnly).
	if !m.exactOnly {
		for d := range m.exactDomains {
			if strings.HasSuffix(domain, "."+d) {
				return true
			}
		}
	}

	// Wildcard suffix match.
	for _, suffix := range m.wildcardSuffixes {
		if strings.HasSuffix(domain, suffix) && domain != suffix[1:] {
			// *.github.com matches api.github.com but not github.com.
			return true
		}
	}

	return false
}

func normalizeDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
