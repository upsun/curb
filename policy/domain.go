package policy

import "strings"

// DomainMatcher checks domain names against an allowlist with exact and
// wildcard matching support.
// Bare domains match exactly: "example.com" matches only "example.com".
// Wildcards match subdomains: "*.example.com" matches "api.example.com" but not "example.com".
// Use both for full coverage: "example.com,*.example.com".
type DomainMatcher struct {
	exactDomains     map[string]bool
	wildcardSuffixes []string
	matchAll         bool
}

// NewDomainMatcher creates a matcher from a list of domain patterns.
// Patterns can be exact ("example.com"), wildcard ("*.github.com"), or "*" (match all).
// Bare domains match exactly (no implicit subdomain matching).
func NewDomainMatcher(domains []string) *DomainMatcher {
	m := &DomainMatcher{
		exactDomains: make(map[string]bool),
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
