package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/upsun/curb/policy"
)

func TestParseInjectHeader(t *testing.T) {
	specs, err := parseInjectHeader([]string{"ANTHROPIC_API_KEY:api.anthropic.com"})
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "ANTHROPIC_API_KEY", specs[0].envVar)
	require.Len(t, specs[0].targets, 1)
	assert.Equal(t, "api.anthropic.com", specs[0].targets[0].Host)
	assert.Equal(t, "443", specs[0].targets[0].Port)

	for _, bad := range []string{
		"", "ANTHROPIC_API_KEY", ":h.com", "TOK:", // missing var or host
		"1BAD:h.com",       // invalid env var name (leading digit)
		"bad-var:h.com",    // invalid env var name (dash)
		"T:*", "T:*.h.com", // wildcard hosts rejected
		"TOK:not a host", // invalid host
		"TOK:h.com:0",    // invalid port
		"TOK:h.com,",     // empty target in list
	} {
		_, err := parseInjectHeader([]string{bad})
		assert.Error(t, err, "expected error for %q", bad)
	}

	// A list of targets with a mix of default and custom ports.
	specs, err = parseInjectHeader([]string{"T:API.Anthropic.COM.,b.example.com:8443"})
	require.NoError(t, err)
	require.Len(t, specs[0].targets, 2)
	assert.Equal(t, "api.anthropic.com", specs[0].targets[0].Host)
	assert.Equal(t, "b.example.com", specs[0].targets[1].Host)
	assert.Equal(t, "8443", specs[0].targets[1].Port)
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
	specs := []injectSpec{{envVar: "SKIPPED_TOKEN", targets: []policy.InjectTarget{{Host: "api.example.com", Port: "443"}}}}

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
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", targets: []policy.InjectTarget{{Host: "api.example.com", Port: "443"}}}}

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
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", targets: []policy.InjectTarget{{Host: "api.example.com", Port: "443"}}}}

	require.NoError(t, resolveInject(plan, specs))
	assert.NotNil(t, plan.CA)
	assert.Contains(t, plan.InjectBindings, policy.InjectTarget{Host: "api.example.com", Port: "443"})
	assert.Equal(t, injectPlaceholder("ACTIVE_TOKEN"), plan.EnvSet["ACTIVE_TOKEN"])
}

func TestResolveInjectExactPassthroughSkipsInjection(t *testing.T) {
	t.Setenv("ACTIVE_TOKEN", "secret")
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{},
		EnvPassthrough: []string{"ACTIVE_TOKEN"},
		ProxyEnabled:   true,
	}
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", targets: []policy.InjectTarget{{Host: "api.example.com", Port: "443"}}}}

	require.NoError(t, resolveInject(plan, specs))
	assert.Empty(t, plan.InjectBindings)
	assert.Nil(t, plan.CA)
	_, set := plan.EnvSet["ACTIVE_TOKEN"]
	assert.False(t, set)
}

// TestResolveInjectExplicitEnvValueSkipsInjection confirms --env VAR=value is
// an injection opt-out like exact passthrough: the user-supplied value reaches
// the sandbox instead of being clobbered by the placeholder.
func TestResolveInjectExplicitEnvValueSkipsInjection(t *testing.T) {
	t.Setenv("ACTIVE_TOKEN", "host-secret")
	plan := &SandboxPlan{
		TempDir:         t.TempDir(),
		EnvSet:          map[string]string{"ACTIVE_TOKEN": "user-value"},
		explicitEnvVars: map[string]bool{"ACTIVE_TOKEN": true},
		AllowedDomains:  []string{"api.example.com"},
		ProxyEnabled:    true,
	}
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", targets: []policy.InjectTarget{{Host: "api.example.com", Port: "443"}}}}

	require.NoError(t, resolveInject(plan, specs))
	assert.Empty(t, plan.InjectBindings)
	assert.Nil(t, plan.CA)
	assert.Equal(t, "user-value", plan.EnvSet["ACTIVE_TOKEN"])
}

// TestResolveInjectWithoutProxySuggestsPassthrough confirms the planning error
// for an active binding without the proxy (e.g. --unrestricted-net) names the
// variable and the --env escape hatch.
func TestResolveInjectWithoutProxySuggestsPassthrough(t *testing.T) {
	t.Setenv("ACTIVE_TOKEN", "secret")
	plan := &SandboxPlan{
		TempDir: t.TempDir(),
		EnvSet:  map[string]string{},
	}
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", targets: []policy.InjectTarget{{Host: "api.example.com", Port: "443"}}}}

	err := resolveInject(plan, specs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACTIVE_TOKEN")
	assert.Contains(t, err.Error(), "--env ACTIVE_TOKEN")
}

// TestCABundleBaseDirectoryFallsBack confirms a CA env var pointing at a
// directory (accepted by e.g. python-requests) does not abort the run: the
// system bundle is used as the base instead.
func TestCABundleBaseDirectoryFallsBack(t *testing.T) {
	if systemCABundle() == "" {
		t.Skip("system CA bundle unavailable")
	}
	t.Setenv("ACTIVE_TOKEN", "secret")
	t.Setenv("REQUESTS_CA_BUNDLE", t.TempDir())
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{},
		EnvPassthrough: []string{"REQUESTS_CA_BUNDLE"},
		AllowedDomains: []string{"api.example.com"},
		ProxyEnabled:   true,
	}
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", targets: []policy.InjectTarget{{Host: "api.example.com", Port: "443"}}}}

	require.NoError(t, resolveInject(plan, specs))
	data, err := os.ReadFile(plan.EnvSet["REQUESTS_CA_BUNDLE"])
	require.NoError(t, err)
	assert.Contains(t, string(data), "CERTIFICATE")
}

func TestResolveInjectWildcardPassthroughStillInjects(t *testing.T) {
	if systemCABundle() == "" {
		t.Skip("system CA bundle unavailable")
	}
	t.Setenv("ACTIVE_TOKEN", "secret")
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{},
		EnvPassthrough: []string{"ACTIVE_*"},
		AllowedDomains: []string{"api.example.com"},
		ProxyEnabled:   true,
	}
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", targets: []policy.InjectTarget{{Host: "api.example.com", Port: "443"}}}}

	require.NoError(t, resolveInject(plan, specs))
	assert.Contains(t, plan.InjectBindings, policy.InjectTarget{Host: "api.example.com", Port: "443"})
	assert.Equal(t, injectPlaceholder("ACTIVE_TOKEN"), plan.EnvSet["ACTIVE_TOKEN"])
}

func TestResolveInjectExtendsPassthroughSSL_CERT_FILE(t *testing.T) {
	t.Setenv("ACTIVE_TOKEN", "secret")
	dir := t.TempDir()
	base := filepath.Join(dir, "custom-roots.pem")
	require.NoError(t, os.WriteFile(base, []byte("-----BEGIN CERTIFICATE-----\nCUSTOMROOT\n-----END CERTIFICATE-----\n"), 0o644))

	for _, tc := range []struct {
		name        string
		passthrough []string
	}{
		{name: "named", passthrough: []string{"SSL_CERT_FILE"}},
		{name: "all", passthrough: []string{envPassthroughAll}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SSL_CERT_FILE", base)
			plan := &SandboxPlan{
				TempDir:        t.TempDir(),
				EnvSet:         map[string]string{},
				EnvPassthrough: tc.passthrough,
				AllowedDomains: []string{"api.example.com"},
				ProxyEnabled:   true,
			}
			specs := []injectSpec{{envVar: "ACTIVE_TOKEN", targets: []policy.InjectTarget{{Host: "api.example.com", Port: "443"}}}}

			require.NoError(t, resolveInject(plan, specs))
			bundle := plan.EnvSet["SSL_CERT_FILE"]
			data, err := os.ReadFile(bundle)
			require.NoError(t, err)
			assert.Contains(t, string(data), "CUSTOMROOT")
		})
	}
}

func TestResolveInjectExtendsEachExistingCABundleEnv(t *testing.T) {
	t.Setenv("ACTIVE_TOKEN", "secret")
	dir := t.TempDir()
	curlBase := filepath.Join(dir, "curl-roots.pem")
	requestsBase := filepath.Join(dir, "requests-roots.pem")
	require.NoError(t, os.WriteFile(curlBase, []byte("-----BEGIN CERTIFICATE-----\nCURLROOT\n-----END CERTIFICATE-----\n"), 0o644))
	require.NoError(t, os.WriteFile(requestsBase, []byte("-----BEGIN CERTIFICATE-----\nREQUESTSROOT\n-----END CERTIFICATE-----\n"), 0o644))
	t.Setenv("REQUESTS_CA_BUNDLE", requestsBase)

	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{"CURL_CA_BUNDLE": curlBase},
		EnvPassthrough: []string{"REQUESTS_CA_BUNDLE"},
		AllowedDomains: []string{"api.example.com"},
		ProxyEnabled:   true,
	}
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", targets: []policy.InjectTarget{{Host: "api.example.com", Port: "443"}}}}

	require.NoError(t, resolveInject(plan, specs))
	curlData, err := os.ReadFile(plan.EnvSet["CURL_CA_BUNDLE"])
	require.NoError(t, err)
	assert.Contains(t, string(curlData), "CURLROOT")

	requestsData, err := os.ReadFile(plan.EnvSet["REQUESTS_CA_BUNDLE"])
	require.NoError(t, err)
	assert.Contains(t, string(requestsData), "REQUESTSROOT")

	_, err = os.Stat(plan.EnvSet["SSL_CERT_FILE"])
	assert.NoError(t, err)
}

func TestResolveInjectIPTarget(t *testing.T) {
	if systemCABundle() == "" {
		t.Skip("system CA bundle unavailable")
	}
	t.Setenv("ACTIVE_TOKEN", "secret")

	// An IP target must be authorized via --ips, not --domains.
	notAllowed := &SandboxPlan{
		TempDir:      t.TempDir(),
		EnvSet:       map[string]string{},
		ProxyEnabled: true,
	}
	specs := []injectSpec{{envVar: "ACTIVE_TOKEN", targets: []policy.InjectTarget{{Host: "10.0.0.5", Port: "8443", IsIP: true}}}}
	err := resolveInject(notAllowed, specs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `credential injection IP "10.0.0.5" is not allowed`)

	// Allowed by --ips (CIDR), bound under host:port.
	plan := &SandboxPlan{
		TempDir:      t.TempDir(),
		EnvSet:       map[string]string{},
		AllowedIPs:   []string{"10.0.0.0/24"},
		ProxyEnabled: true,
	}
	require.NoError(t, resolveInject(plan, specs))
	assert.NotNil(t, plan.CA)
	assert.Contains(t, plan.InjectBindings, policy.InjectTarget{Host: "10.0.0.5", Port: "8443", IsIP: true})
}

func TestWriteCABundle(t *testing.T) {
	dir := t.TempDir()
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nPERRUNCA\n-----END CERTIFICATE-----\n")

	if systemCABundle() == "" {
		// Without system roots, the bundle would override TLS trust with an
		// incomplete set, so injection fails rather than break other hosts.
		_, err := writeCABundleFile(dir, "ca-bundle.pem", "", caPEM)
		require.Error(t, err)
		return
	}

	path, err := writeCABundleFile(dir, "ca-bundle.pem", "", caPEM)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "ca-bundle.pem"), path)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	// The per-run CA is appended after the system roots.
	assert.Contains(t, string(data), "PERRUNCA")
	assert.Greater(t, len(data), len(caPEM), "combined bundle should include system roots")
}

func TestWriteCABundle_ExtendsUserBase(t *testing.T) {
	dir := t.TempDir()
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nPERRUNCA\n-----END CERTIFICATE-----\n")
	base := filepath.Join(dir, "custom-roots.pem")
	require.NoError(t, os.WriteFile(base, []byte("-----BEGIN CERTIFICATE-----\nCUSTOMROOT\n-----END CERTIFICATE-----\n"), 0o644))

	path, err := writeCABundleFile(dir, "ca-bundle.pem", base, caPEM)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	// A user-provided base is extended, not discarded.
	assert.Contains(t, string(data), "CUSTOMROOT")
	assert.Contains(t, string(data), "PERRUNCA")
}
