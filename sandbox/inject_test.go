package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseInjectHeader(t *testing.T) {
	specs, err := parseInjectHeader([]string{"ANTHROPIC_API_KEY=api.anthropic.com"})
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "ANTHROPIC_API_KEY", specs[0].envVar)
	assert.Equal(t, "api.anthropic.com", specs[0].host)

	for _, bad := range []string{
		"", "ANTHROPIC_API_KEY", "=h.com", "TOK=", // missing var or host
		"1BAD=h.com",       // invalid env var name (leading digit)
		"bad-var=h.com",    // invalid env var name (dash)
		"T=*", "T=*.h.com", // wildcard hosts rejected
		"TOK=not a host", // invalid host
		"A=b.com=x",      // '=' in host (would bind a never-matching host)
	} {
		_, err := parseInjectHeader([]string{bad})
		assert.Error(t, err, "expected error for %q", bad)
	}

	// Hosts are normalized to lowercase with no trailing dot.
	specs, err = parseInjectHeader([]string{"T=API.Anthropic.COM."})
	require.NoError(t, err)
	assert.Equal(t, "api.anthropic.com", specs[0].host)
}

func TestInjectPlaceholder(t *testing.T) {
	// Stable per env var, and distinct vars get distinct placeholders.
	assert.Equal(t, injectPlaceholder("ANTHROPIC_API_KEY"), injectPlaceholder("ANTHROPIC_API_KEY"))
	assert.NotEqual(t, injectPlaceholder("A"), injectPlaceholder("B"))
	assert.Contains(t, injectPlaceholder("GH_TOKEN"), "GH_TOKEN")

	// No placeholder may be a prefix of another, or replaceInHeaders' substring
	// substitution would corrupt one credential while replacing another bound to
	// the same host (e.g. TOK vs TOK2).
	tok, tok2 := injectPlaceholder("TOK"), injectPlaceholder("TOK2")
	assert.False(t, strings.HasPrefix(tok2, tok), "%q must not be a prefix of %q", tok, tok2)
}

func TestResolveInjectSkippedDoesNotRequireAllowedDomain(t *testing.T) {
	t.Setenv("SKIPPED_TOKEN", "")
	plan := &SandboxPlan{
		TempDir: t.TempDir(),
		EnvSet:  map[string]string{},
	}
	specs := []injectSpec{{envVar: "SKIPPED_TOKEN", host: "api.example.com"}}

	require.NoError(t, resolveInject(plan, specs))
	assert.Empty(t, plan.AllowedDomains)
	assert.Empty(t, plan.InjectBindings)
	assert.Nil(t, plan.CA)
}

func TestResolveInjectRequiresAllowedDomain(t *testing.T) {
	t.Setenv("ACTIVE_TOKEN", "secret")
	plan := &SandboxPlan{
		TempDir:      t.TempDir(),
		EnvSet:       map[string]string{},
		ProxyEnabled: true,
	}
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", host: "api.example.com"}}

	err := resolveInject(plan, specs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `credential injection host "api.example.com" is not allowed`)
	assert.Nil(t, plan.CA)
	assert.Empty(t, plan.InjectBindings)
}

func TestResolveInjectAllowsWildcardDomain(t *testing.T) {
	if systemCABundle() == "" {
		t.Skip("system CA bundle unavailable")
	}
	t.Setenv("ACTIVE_TOKEN", "secret")
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{},
		AllowedDomains: []string{"*.example.com"},
		ProxyEnabled:   true,
	}
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", host: "api.example.com"}}

	require.NoError(t, resolveInject(plan, specs))
	assert.NotNil(t, plan.CA)
	assert.Contains(t, plan.InjectBindings, "api.example.com")
	assert.Equal(t, injectPlaceholder("ACTIVE_TOKEN"), plan.EnvSet["ACTIVE_TOKEN"])
}

func TestWriteCABundle(t *testing.T) {
	dir := t.TempDir()
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nPERRUNCA\n-----END CERTIFICATE-----\n")

	if systemCABundle() == "" {
		// Without system roots, the bundle would override TLS trust with an
		// incomplete set, so injection fails rather than break other hosts.
		_, err := writeCABundle(dir, caPEM)
		require.Error(t, err)
		return
	}

	path, err := writeCABundle(dir, caPEM)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "ca-bundle.pem"), path)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	// The per-run CA is appended after the system roots.
	assert.Contains(t, string(data), "PERRUNCA")
	assert.Greater(t, len(data), len(caPEM), "combined bundle should include system roots")
}
