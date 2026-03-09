package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDomainMatcher(t *testing.T) {
	tests := []struct {
		name      string
		domains   []string
		exactOnly bool
		query     string
		want      bool
	}{
		// Exact match.
		{"exact match", []string{"example.com"}, false, "example.com", true},
		{"exact no match", []string{"example.com"}, false, "other.com", false},
		{"exact case insensitive", []string{"Example.COM"}, false, "example.com", true},
		{"exact query case insensitive", []string{"example.com"}, false, "EXAMPLE.COM", true},

		// Subdomain matching (default).
		{"subdomain match", []string{"example.com"}, false, "sub.example.com", true},
		{"deep subdomain match", []string{"example.com"}, false, "a.b.example.com", true},
		{"subdomain no partial match", []string{"example.com"}, false, "notexample.com", false},

		// Subdomain matching disabled (--exact-match).
		{"exact-only no subdomain", []string{"example.com"}, true, "sub.example.com", false},
		{"exact-only exact still works", []string{"example.com"}, true, "example.com", true},

		// Wildcard patterns.
		{"wildcard match", []string{"*.github.com"}, false, "api.github.com", true},
		{"wildcard deep match", []string{"*.github.com"}, false, "raw.api.github.com", true},
		{"wildcard no bare domain", []string{"*.github.com"}, false, "github.com", false},
		{"wildcard case insensitive", []string{"*.GitHub.COM"}, false, "api.github.com", true},

		// Star matches all.
		{"star matches anything", []string{"*"}, false, "anything.example.com", true},
		{"star matches bare domain", []string{"*"}, false, "localhost", true},
		{"star with exact-only", []string{"*"}, true, "anything.example.com", true},

		// Empty matcher.
		{"empty matches nothing", nil, false, "example.com", false},
		{"empty slice matches nothing", []string{}, false, "example.com", false},

		// Edge cases.
		{"empty query", []string{"example.com"}, false, "", false},
		{"trailing dot in pattern", []string{"example.com."}, false, "example.com", true},
		{"trailing dot in query", []string{"example.com"}, false, "example.com.", true},
		{"mixed patterns", []string{"example.com", "*.github.com"}, false, "api.github.com", true},
		{"mixed patterns exact", []string{"example.com", "*.github.com"}, false, "example.com", true},
		{"mixed patterns subdomain", []string{"example.com", "*.github.com"}, false, "sub.example.com", true},
		{"mixed patterns no match", []string{"example.com", "*.github.com"}, false, "other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewDomainMatcher(tt.domains, tt.exactOnly)
			got := m.Match(tt.query)
			assert.Equal(t, tt.want, got)
		})
	}
}
