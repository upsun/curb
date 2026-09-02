package sandbox

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/upsun/curb/config"
	"github.com/upsun/curb/policy"
)

// TestParseInjectHeader covers what the wrapper adds over
// policy.ParseInjectHeader (which owns the validation rule matrix, see
// policy/validate_test.go): multi-entry parsing and the flag-name error prefix.
func TestParseInjectHeader(t *testing.T) {
	specs, err := parseInjectHeader([]string{"ANTHROPIC_API_KEY:api.anthropic.com", "T:b.example.com:8443"})
	require.NoError(t, err)
	require.Len(t, specs, 2)
	assert.Equal(t, "ANTHROPIC_API_KEY", specs[0].envVar)
	assert.Equal(t, []policy.InjectTarget{{Host: "api.anthropic.com", Port: "443"}}, specs[0].targets)
	assert.Equal(t, []policy.InjectTarget{{Host: "b.example.com", Port: "8443"}}, specs[1].targets)

	_, err = parseInjectHeader([]string{"bad-var:h.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--inject-header ")
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

// injectCfg builds a config with one binding entry, for resolveInject tests.
func injectCfg(entries ...string) *config.Config {
	return &config.Config{InjectHeader: entries}
}

func TestResolveInjectSkippedDoesNotRequireAllowedDomain(t *testing.T) {
	t.Setenv("SKIPPED_TOKEN", "")
	plan := &SandboxPlan{
		TempDir: t.TempDir(),
		EnvSet:  map[string]string{},
	}

	require.NoError(t, resolveInject(plan, injectCfg("SKIPPED_TOKEN:api.example.com")))
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

	err := resolveInject(plan, injectCfg("ACTIVE_TOKEN:api.example.com"))
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

	require.NoError(t, resolveInject(plan, injectCfg("ACTIVE_TOKEN:api.example.com")))
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
	cfg := injectCfg("ACTIVE_TOKEN:api.example.com")
	cfg.EnvPassthrough = []string{"ACTIVE_TOKEN"}

	require.NoError(t, resolveInject(plan, cfg))
	assert.Empty(t, plan.InjectBindings)
	assert.Nil(t, plan.CA)
	_, set := plan.EnvSet["ACTIVE_TOKEN"]
	assert.False(t, set)
}

// TestResolveInjectExactPassthroughWithWildcardSkipsInjection confirms an
// explicit --env VAR remains an opt-out when combined with --env '*': the
// explicit name is preserved alongside EnvPassthroughAll.
func TestResolveInjectExactPassthroughWithWildcardSkipsInjection(t *testing.T) {
	t.Setenv("ACTIVE_TOKEN", "secret")
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{},
		EnvPassthrough: []string{envPassthroughAll},
		ProxyEnabled:   true,
	}
	cfg := injectCfg("ACTIVE_TOKEN:api.example.com")
	cfg.EnvPassthroughAll = true
	cfg.EnvPassthrough = []string{"ACTIVE_TOKEN"}

	require.NoError(t, resolveInject(plan, cfg))
	assert.Empty(t, plan.InjectBindings)
	assert.Nil(t, plan.CA)
}

// TestResolveInjectExplicitEnvValueSkipsInjection confirms --env VAR=value is
// an injection opt-out like exact passthrough: the user-supplied value reaches
// the sandbox instead of being clobbered by the placeholder.
func TestResolveInjectExplicitEnvValueSkipsInjection(t *testing.T) {
	t.Setenv("ACTIVE_TOKEN", "host-secret")
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{"ACTIVE_TOKEN": "user-value"},
		AllowedDomains: []string{"api.example.com"},
		ProxyEnabled:   true,
	}
	cfg := injectCfg("ACTIVE_TOKEN:api.example.com")
	cfg.EnvSet = []string{"ACTIVE_TOKEN=user-value"}

	require.NoError(t, resolveInject(plan, cfg))
	assert.Empty(t, plan.InjectBindings)
	assert.Nil(t, plan.CA)
	assert.Equal(t, "user-value", plan.EnvSet["ACTIVE_TOKEN"])
}

// TestResolveInjectWithoutProxySuggestsPassthrough confirms the planning error
// for an active binding whose destination is allowed but unfiltered (profile
// domains + --unrestricted-net) names the variable and the --env escape hatch.
// An unlisted destination keeps the more specific "add --domains" error, which
// authorization raises first.
func TestResolveInjectWithoutProxySuggestsPassthrough(t *testing.T) {
	t.Setenv("ACTIVE_TOKEN", "secret")
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{},
		AllowedDomains: []string{"api.example.com"},
	}

	err := resolveInject(plan, injectCfg("ACTIVE_TOKEN:api.example.com"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACTIVE_TOKEN")
	assert.Contains(t, err.Error(), "--env ACTIVE_TOKEN")
}

// TestResolveInjectWithoutProxyHintNamesEachVariable confirms the --env hint
// covers every active binding, not just the first.
func TestResolveInjectWithoutProxyHintNamesEachVariable(t *testing.T) {
	t.Setenv("TOKEN_A", "secret-a")
	t.Setenv("TOKEN_B", "secret-b")
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{},
		AllowedDomains: []string{"a.example.com", "b.example.com"},
	}

	err := resolveInject(plan, injectCfg("TOKEN_A:a.example.com", "TOKEN_B:b.example.com"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--env TOKEN_A")
	assert.Contains(t, err.Error(), "--env TOKEN_B")
}

// TestCABundleBaseExplicitEmptyOverridesPassthrough confirms an explicitly
// cleared CA var (--env SSL_CERT_FILE=) does not fall back to the host value
// via passthrough: EnvSet wins over passthrough, as in ResolveEnv.
func TestCABundleBaseExplicitEmptyOverridesPassthrough(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "/host/roots.pem")
	plan := &SandboxPlan{
		EnvSet:         map[string]string{"SSL_CERT_FILE": ""},
		EnvPassthrough: []string{envPassthroughAll},
	}
	assert.Empty(t, plan.caBundleBase("SSL_CERT_FILE"))
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

	require.NoError(t, resolveInject(plan, injectCfg("ACTIVE_TOKEN:api.example.com")))
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
	cfg := injectCfg("ACTIVE_TOKEN:api.example.com")
	cfg.EnvPassthrough = []string{"ACTIVE_*"}

	require.NoError(t, resolveInject(plan, cfg))
	assert.Contains(t, plan.InjectBindings, policy.InjectTarget{Host: "api.example.com", Port: "443"})
	assert.Equal(t, injectPlaceholder("ACTIVE_TOKEN"), plan.EnvSet["ACTIVE_TOKEN"])
}

func TestResolveInjectPassthroughAllStillInjects(t *testing.T) {
	if systemCABundle() == "" {
		t.Skip("system CA bundle unavailable")
	}
	t.Setenv("ACTIVE_TOKEN", "secret")
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{},
		EnvPassthrough: []string{envPassthroughAll},
		AllowedDomains: []string{"api.example.com"},
		ProxyEnabled:   true,
	}
	cfg := injectCfg("ACTIVE_TOKEN:api.example.com")
	cfg.EnvPassthroughAll = true

	require.NoError(t, resolveInject(plan, cfg))
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

			require.NoError(t, resolveInject(plan, injectCfg("ACTIVE_TOKEN:api.example.com")))
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

	require.NoError(t, resolveInject(plan, injectCfg("ACTIVE_TOKEN:api.example.com")))
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
	cfg := injectCfg("ACTIVE_TOKEN:10.0.0.5:8443")
	err := resolveInject(notAllowed, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `credential injection IP "10.0.0.5" is not allowed`)

	// Allowed by --ips (CIDR), bound under host:port.
	plan := &SandboxPlan{
		TempDir:      t.TempDir(),
		EnvSet:       map[string]string{},
		AllowedIPs:   []string{"10.0.0.0/24"},
		ProxyEnabled: true,
	}
	require.NoError(t, resolveInject(plan, cfg))
	assert.NotNil(t, plan.CA)
	assert.Contains(t, plan.InjectBindings, policy.InjectTarget{Host: "10.0.0.5", Port: "8443"})
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

// TestCABundleBaseMissingFileFallsBack confirms a stale CA env var pointing at
// a path that no longer exists does not abort the run: like the directory case,
// the system bundle is used as the base instead. Such a value is inherited from
// the host, not chosen by curb, so it must not be able to fail planning.
func TestCABundleBaseMissingFileFallsBack(t *testing.T) {
	if systemCABundle() == "" {
		t.Skip("system CA bundle unavailable")
	}
	t.Setenv("ACTIVE_TOKEN", "secret")
	t.Setenv("NODE_EXTRA_CA_CERTS", filepath.Join(t.TempDir(), "gone.pem"))
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{},
		EnvPassthrough: []string{envPassthroughAll},
		AllowedDomains: []string{"api.example.com"},
		ProxyEnabled:   true,
	}

	require.NoError(t, resolveInject(plan, injectCfg("ACTIVE_TOKEN:api.example.com")))
	data, err := os.ReadFile(plan.EnvSet["NODE_EXTRA_CA_CERTS"])
	require.NoError(t, err)
	assert.Contains(t, string(data), "CERTIFICATE")
}

// TestCABundleBaseUnreadableFileFallsBack covers a base that exists but cannot
// be read: same host-inherited value, same fallback.
func TestCABundleBaseUnreadableFileFallsBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	base := filepath.Join(t.TempDir(), "roots.pem")
	require.NoError(t, os.WriteFile(base, []byte("-----BEGIN CERTIFICATE-----\n"), 0o000))
	t.Setenv("CURL_CA_BUNDLE", base)
	plan := &SandboxPlan{
		EnvSet:         map[string]string{},
		EnvPassthrough: []string{"CURL_CA_BUNDLE"},
	}
	assert.Empty(t, plan.caBundleBase("CURL_CA_BUNDLE"))
}

// --- unbound endpoint warnings ---

// captureStderr redirects os.Stderr for the duration of fn and returns what
// was written. clog.Warnf resolves os.Stderr per call, so this captures it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	saved := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = saved }()

	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	fn()
	require.NoError(t, w.Close())
	out := <-done
	require.NoError(t, r.Close())
	return out
}

func TestUnboundEndpointWarnings(t *testing.T) {
	specs := func(entry string) []injectSpec {
		parsed, err := parseInjectHeader([]string{entry})
		require.NoError(t, err)
		return parsed
	}
	tests := []struct {
		name    string
		specs   []injectSpec
		env     map[string]string
		want    string // substring the single warning must contain, "" for none
		wantAll []string
	}{
		{
			name:  "endpoint on the bound host is silent",
			specs: specs("ANTHROPIC_API_KEY:api.anthropic.com"),
			env:   map[string]string{"ANTHROPIC_BASE_URL": "https://api.anthropic.com"},
		},
		{
			name:  "host normalization applies",
			specs: specs("ANTHROPIC_API_KEY:api.anthropic.com"),
			env:   map[string]string{"ANTHROPIC_BASE_URL": "https://API.Anthropic.com./v1"},
		},
		{
			name:    "gateway host is not covered",
			specs:   specs("ANTHROPIC_API_KEY:api.anthropic.com"),
			env:     map[string]string{"ANTHROPIC_BASE_URL": "https://gw.example.com/v1"},
			wantAll: []string{"ANTHROPIC_BASE_URL points at gw.example.com", "--inject-header ANTHROPIC_API_KEY:gw.example.com", "--env ANTHROPIC_API_KEY"},
		},
		{
			name:  "bindings are port-exact",
			specs: specs("ANTHROPIC_API_KEY:api.anthropic.com"),
			env:   map[string]string{"ANTHROPIC_BASE_URL": "https://api.anthropic.com:8443"},
			want:  "--inject-header ANTHROPIC_API_KEY:api.anthropic.com:8443",
		},
		{
			name:  "custom port matches its binding",
			specs: specs("ANTHROPIC_API_KEY:api.anthropic.com:8443"),
			env:   map[string]string{"ANTHROPIC_BASE_URL": "https://api.anthropic.com:8443"},
		},
		{
			name:  "cleartext endpoint cannot carry a credential",
			specs: specs("ANTHROPIC_API_KEY:api.anthropic.com"),
			env:   map[string]string{"ANTHROPIC_BASE_URL": "http://gw.example.com"},
			want:  "plain-HTTP gw.example.com:80",
		},
		{
			name:  "cleartext is reported even on a bound destination",
			specs: specs("ANTHROPIC_API_KEY:gw.example.com:80"),
			env:   map[string]string{"ANTHROPIC_BASE_URL": "http://gw.example.com"},
			want:  "plain-HTTP gw.example.com:80",
		},
		{
			name:  "a bare host is an endpoint too",
			specs: specs("FOO_TOKEN:api.example.com"),
			env:   map[string]string{"FOO_ENDPOINT": "gw.example.com"},
			want:  "FOO_ENDPOINT points at gw.example.com",
		},
		{
			name:  "an IPv6 endpoint is bracketed for the suggestion",
			specs: specs("FOO_TOKEN:api.example.com"),
			env:   map[string]string{"FOO_URL": "https://[2001:db8::1]:8443"},
			want:  "--inject-header FOO_TOKEN:[2001:db8::1]:8443",
		},
		{
			name:  "an unrelated variable is not this credential's endpoint",
			specs: specs("ANTHROPIC_API_KEY:api.anthropic.com"),
			env:   map[string]string{"OPENAI_BASE_URL": "https://gw.example.com"},
		},
		{
			name:  "_HOST is not treated as an endpoint",
			specs: specs("GH_TOKEN:api.github.com"),
			env:   map[string]string{"GH_HOST": "github.com"},
		},
		{
			name:  "a value that names no host is ignored",
			specs: specs("FOO_TOKEN:api.example.com"),
			env:   map[string]string{"FOO_URL": "", "FOO_ENDPOINT": "unix:///var/run/x.sock"},
		},
		{
			name:  "an unparsable destination is ignored",
			specs: specs("FOO_TOKEN:api.example.com"),
			env: map[string]string{
				"FOO_URL":      "https://gw.example.com:notaport",
				"FOO_ENDPOINT": "https://*.example.com",
				"FOO_API_BASE": "https://gw example com/",
			},
		},
		{
			name:    "a query string is not part of the host",
			specs:   specs("FOO_TOKEN:api.example.com"),
			env:     map[string]string{"FOO_URL": "https://gw.example.com?v=1"},
			wantAll: []string{"points at gw.example.com,", "--inject-header FOO_TOKEN:gw.example.com "},
		},
		{
			name:  "the credential's own variable is not an endpoint",
			specs: specs("FOO_URL:api.example.com"),
			env:   map[string]string{"FOO_URL": injectPlaceholder("FOO_URL")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := unboundEndpointWarnings(tt.specs, tt.env)
			if tt.want == "" && len(tt.wantAll) == 0 {
				assert.Empty(t, msgs)
				return
			}
			require.Len(t, msgs, 1)
			for _, want := range append(tt.wantAll, tt.want) {
				if want != "" {
					assert.Contains(t, msgs[0], want)
				}
			}
		})
	}
}

// TestUnboundEndpointWarningsStripUserinfo confirms the destination is the
// URL's host alone: userinfo in an endpoint value is not part of the
// destination, and must not be echoed into a warning.
func TestUnboundEndpointWarningsStripUserinfo(t *testing.T) {
	specs, err := parseInjectHeader([]string{"FOO_TOKEN:api.example.com"})
	require.NoError(t, err)
	msgs := unboundEndpointWarnings(specs, map[string]string{"FOO_BASE_URL": "https://user:hunter2@gw.example.com/v1"})
	require.Len(t, msgs, 1)
	assert.Contains(t, msgs[0], "--inject-header FOO_TOKEN:gw.example.com ")
	assert.NotContains(t, msgs[0], "hunter2")
}

// TestUnboundEndpointWarningsMultipleBindings confirms each credential is
// checked against its own destinations, and the bound list is reported.
func TestUnboundEndpointWarningsMultipleBindings(t *testing.T) {
	specs, err := parseInjectHeader([]string{"A_KEY:a.example.com,alt.example.com", "B_KEY:b.example.com"})
	require.NoError(t, err)
	msgs := unboundEndpointWarnings(specs, map[string]string{
		"A_BASE_URL": "https://alt.example.com",
		"B_BASE_URL": "https://gw.example.com",
	})
	require.Len(t, msgs, 1)
	assert.Contains(t, msgs[0], "B_BASE_URL points at gw.example.com")
	assert.Contains(t, msgs[0], "(b.example.com)")
}

// TestResolveInjectWarnsUnboundEndpoint covers the wiring: the endpoint check
// runs on the resolved sandbox environment, so a passed-through endpoint
// variable reaches it.
func TestResolveInjectWarnsUnboundEndpoint(t *testing.T) {
	if systemCABundle() == "" {
		t.Skip("system CA bundle unavailable")
	}
	t.Setenv("ACTIVE_TOKEN", "secret")
	t.Setenv("ACTIVE_BASE_URL", "https://gw.example.com")
	plan := &SandboxPlan{
		TempDir:        t.TempDir(),
		EnvSet:         map[string]string{},
		EnvPassthrough: []string{"ACTIVE_BASE_URL"},
		AllowedDomains: []string{"api.example.com"},
		ProxyEnabled:   true,
	}

	stderr := captureStderr(t, func() {
		require.NoError(t, resolveInject(plan, injectCfg("ACTIVE_TOKEN:api.example.com")))
	})
	assert.Contains(t, stderr, "ACTIVE_BASE_URL points at gw.example.com")
	// The warning must never carry the credential itself.
	assert.NotContains(t, stderr, "secret")
}
