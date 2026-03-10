package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainMatcher(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		query   string
		want    bool
	}{
		// Exact match.
		{"exact match", []string{"example.com"}, "example.com", true},
		{"exact no match", []string{"example.com"}, "other.com", false},
		{"exact case insensitive", []string{"Example.COM"}, "example.com", true},
		{"exact query case insensitive", []string{"example.com"}, "EXAMPLE.COM", true},

		// Bare domains are exact-only (no implicit subdomain matching).
		{"bare domain no subdomain", []string{"example.com"}, "sub.example.com", false},
		{"bare domain no deep subdomain", []string{"example.com"}, "a.b.example.com", false},
		{"bare domain no partial match", []string{"example.com"}, "notexample.com", false},

		// Wildcard patterns.
		{"wildcard match", []string{"*.github.com"}, "api.github.com", true},
		{"wildcard deep match", []string{"*.github.com"}, "raw.api.github.com", true},
		{"wildcard no bare domain", []string{"*.github.com"}, "github.com", false},
		{"wildcard case insensitive", []string{"*.GitHub.COM"}, "api.github.com", true},

		// Combined exact + wildcard for full coverage.
		{"exact+wildcard bare", []string{"example.com", "*.example.com"}, "example.com", true},
		{"exact+wildcard sub", []string{"example.com", "*.example.com"}, "sub.example.com", true},
		{"exact+wildcard other", []string{"example.com", "*.example.com"}, "other.com", false},

		// Star matches all.
		{"star matches anything", []string{"*"}, "anything.example.com", true},
		{"star matches bare domain", []string{"*"}, "localhost", true},

		// Empty matcher.
		{"empty matches nothing", nil, "example.com", false},
		{"empty slice matches nothing", []string{}, "example.com", false},

		// Edge cases.
		{"empty query", []string{"example.com"}, "", false},
		{"trailing dot in pattern", []string{"example.com."}, "example.com", true},
		{"trailing dot in query", []string{"example.com"}, "example.com.", true},
		{"mixed patterns", []string{"example.com", "*.github.com"}, "api.github.com", true},
		{"mixed patterns exact", []string{"example.com", "*.github.com"}, "example.com", true},
		{"mixed patterns no match", []string{"example.com", "*.github.com"}, "other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewDomainMatcher(tt.domains)
			got := m.Match(tt.query)
			assert.Equal(t, tt.want, got)
		})
	}
}
