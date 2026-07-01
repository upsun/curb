package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDomains(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		wantErr string
	}{
		{"valid bare domain", []string{"example.com"}, ""},
		{"valid wildcard", []string{"*.github.com"}, ""},
		{"valid match-all", []string{"*"}, ""},
		{"valid localhost", []string{"localhost"}, ""},
		{"valid IDN", []string{"xn--n3h.example.com"}, ""},
		{"valid multiple", []string{"a.com", "*.b.com", "c.io"}, ""},
		{"valid new TLD", []string{"example.internal"}, ""},

		{"reject http URL", []string{"http://example.com"}, "looks like a URL"},
		{"reject https URL", []string{"https://example.com/path"}, "looks like a URL"},
		{"reject IPv4", []string{"192.168.1.1"}, "use --ips instead"},
		{"reject IPv6", []string{"::1"}, "use --ips instead"},
		{"reject CIDR", []string{"10.0.0.0/8"}, "use --ips instead"},
		{"reject slash", []string{"example.com/path"}, "invalid character \"/\""},
		{"reject colon", []string{"example.com:443"}, "invalid character \":\""},
		{"reject at", []string{"user@example.com"}, "invalid character \"@\""},
		{"reject hash", []string{"example.com#anchor"}, "invalid character \"#\""},
		{"reject question", []string{"example.com?q=1"}, "invalid character \"?\""},
		{"reject backslash", []string{"example.com\\path"}, "invalid character \"\\\\\""},
		{"reject space", []string{"example .com"}, "whitespace or control"},
		{"reject tab", []string{"example\t.com"}, "whitespace or control"},
		{"reject bad wildcard mid", []string{"ex*.com"}, "wildcards must be"},
		{"reject bad wildcard suffix empty", []string{"*."}, "suffix must not be empty"},
		{"first invalid stops", []string{"ok.com", "http://bad.com"}, "looks like a URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomains(tt.domains)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseInjectHeader(t *testing.T) {
	tests := []struct {
		name        string
		entry       string
		wantEnv     string
		wantTargets []InjectTarget
		wantErr     string
	}{
		{"exact host", "TOK:api.github.com", "TOK",
			[]InjectTarget{{Host: "api.github.com", Port: "443"}}, ""},
		{"normalized host", "TOK:API.GitHub.COM.", "TOK",
			[]InjectTarget{{Host: "api.github.com", Port: "443"}}, ""},
		{"custom port", "TOK:api.example.com:8443", "TOK",
			[]InjectTarget{{Host: "api.example.com", Port: "8443"}}, ""},
		{"host list", "TOK:a.example.com,b.example.com:8443", "TOK",
			[]InjectTarget{{Host: "a.example.com", Port: "443"}, {Host: "b.example.com", Port: "8443"}}, ""},
		{"ipv4", "TOK:10.0.0.5", "TOK",
			[]InjectTarget{{Host: "10.0.0.5", Port: "443"}}, ""},
		{"ipv4 with port", "TOK:10.0.0.5:8443", "TOK",
			[]InjectTarget{{Host: "10.0.0.5", Port: "8443"}}, ""},
		{"bare ipv6", "TOK:2001:db8::1", "TOK",
			[]InjectTarget{{Host: "2001:db8::1", Port: "443"}}, ""},
		{"bracketed ipv6 with port", "TOK:[2001:db8::1]:8443", "TOK",
			[]InjectTarget{{Host: "2001:db8::1", Port: "8443"}}, ""},
		// A port with leading zeros is canonicalized, or the binding key would
		// never match a real connection's port.
		{"leading-zero port", "TOK:api.example.com:0443", "TOK",
			[]InjectTarget{{Host: "api.example.com", Port: "443"}}, ""},

		{"reject no colon", "TOK", "", nil, "ENV_VAR:HOST"},
		{"reject empty host", "TOK:", "", nil, "ENV_VAR:HOST"},
		{"reject bad env name", "TO-K:api.github.com", "", nil, "valid environment variable"},
		{"reject match-all", "TOK:*", "", nil, "exact hostname"},
		{"reject wildcard", "TOK:*.github.com", "", nil, "exact hostname"},
		{"reject URL", "TOK:https://api.github.com", "", nil, "looks like a URL"},
		{"reject bad port", "TOK:api.example.com:0", "", nil, "invalid port"},
		{"reject huge port", "TOK:api.example.com:99999", "", nil, "invalid port"},
		{"reject empty target in list", "TOK:a.example.com,", "", nil, "empty injection target"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, targets, err := ParseInjectHeader(tt.entry)
			if tt.wantErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.wantEnv, env)
				assert.Equal(t, tt.wantTargets, targets)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateIPs(t *testing.T) {
	tests := []struct {
		name    string
		ips     []string
		wantErr string
	}{
		{"valid IPv4", []string{"10.0.0.1"}, ""},
		{"valid IPv6", []string{"::1"}, ""},
		{"valid IPv4 CIDR", []string{"192.168.0.0/16"}, ""},
		{"valid IPv6 CIDR", []string{"fd00::/8"}, ""},
		{"valid multiple", []string{"10.0.0.1", "192.168.0.0/16", "::1"}, ""},

		{"reject domain", []string{"example.com"}, "not a valid IP"},
		{"reject garbage", []string{"abc"}, "not a valid IP"},
		{"reject URL", []string{"http://10.0.0.1"}, "not a valid IP"},
		{"reject empty", []string{""}, "not a valid IP"},
		{"first invalid stops", []string{"10.0.0.1", "bad"}, "not a valid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPs(tt.ips)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestStripScheme(t *testing.T) {
	assert.Equal(t, "example.com", stripScheme("https://example.com/path"))
	assert.Equal(t, "example.com", stripScheme("http://example.com"))
}
