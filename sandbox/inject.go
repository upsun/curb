package sandbox

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/upsun/curb/clog"
	"github.com/upsun/curb/config"
	"github.com/upsun/curb/policy"
	"github.com/upsun/curb/proxy"
)

// injectSpec is a parsed injection binding: the sandbox sees envVar set to a
// placeholder; the proxy replaces it with envVar's real value in requests to
// any of targets, wherever the client placed it among the request headers.
type injectSpec struct {
	envVar  string
	targets []policy.InjectTarget
	token   string // real host-env value, resolved by activeInjectSpecs
}

// parseInjectHeader parses --inject-header "ENV_VAR:HOST[,HOST...]" entries.
func parseInjectHeader(entries []string) ([]injectSpec, error) {
	var specs []injectSpec
	for _, e := range entries {
		envVar, targets, err := policy.ParseInjectHeader(e)
		if err != nil {
			return nil, fmt.Errorf("--inject-header %w", err)
		}
		specs = append(specs, injectSpec{envVar: envVar, targets: targets})
	}
	return specs, nil
}

// activeInjectSpecs filters specs to those whose source var is set, non-empty,
// and not explicitly provided via --env (an explicit passthrough or value is a
// trust decision that disables injection for that variable), resolving each
// spec's token on the way.
func activeInjectSpecs(specs []injectSpec, cfg *config.Config) []injectSpec {
	active := make([]injectSpec, 0, len(specs))
	for _, s := range specs {
		token, present := os.LookupEnv(s.envVar)
		if !present || token == "" {
			continue
		}
		if cfg.EnvExplicitlyProvided(s.envVar) {
			continue
		}
		s.token = token
		active = append(active, s)
	}
	return active
}

// injectEnvHint is the shared error suffix suggesting the injection-free
// alternative; takes the injectEnvFlags of the active specs as a format
// argument.
const injectEnvHint = "; or pass the credential into the sandbox instead (an explicit trust decision) with %s"

// injectEnvFlags renders an --env flag per spec for error-message hints.
func injectEnvFlags(specs []injectSpec) string {
	flags := make([]string, len(specs))
	for i, s := range specs {
		flags[i] = "--env " + s.envVar
	}
	return strings.Join(flags, " ")
}

// injectDestinations returns the bound destinations in display form, sorted.
// Shared by the dry-run output and the skill file.
func (p *SandboxPlan) injectDestinations() []string {
	dests := make([]string, 0, len(p.InjectBindings))
	for t := range p.InjectBindings {
		dests = append(dests, t.String())
	}
	sort.Strings(dests)
	return dests
}

// authorizeInjectTarget checks that an injection target is reachable under the
// network policy: an IP target against --ips, a hostname target against
// --domains. A credential must never be provisioned for a destination the
// sandbox cannot otherwise reach.
func authorizeInjectTarget(t policy.InjectTarget, domains *policy.DomainMatcher, ips *policy.IPMatcher) error {
	if addr, err := netip.ParseAddr(t.Host); err == nil {
		if ips.Match(addr) {
			return nil
		}
		return fmt.Errorf("credential injection IP %q is not allowed; add --ips %s", t.Host, t.Host)
	}
	if domains.Match(t.Host) {
		return nil
	}
	return fmt.Errorf("credential injection host %q is not allowed; add --domains %s", t.Host, t.Host)
}

// injectPlaceholder returns the sentinel the sandbox sees in place of a real
// credential. It is constant per env var so a tool that approves a custom key
// (e.g. Claude Code) approves it once. The value carries no secret weight: the
// proxy swaps it for the real token before the request leaves the host.
//
// A valid env var name cannot contain "-", so the surrounding "-" guards ensure
// no placeholder is a prefix of another (TOK vs TOK2) — the substring
// substitution in replaceInHeaders cannot corrupt one placeholder via another.
func injectPlaceholder(envVar string) string {
	return "curb-inject-" + envVar + "-placeholder"
}

// resolveInject parses the configured bindings, generates the per-run CA,
// resolves each bound token, and delivers the CA to the sandbox trust store.
// It runs after proxy and env resolution. The CA key and tokens stay in the
// parent; only the public CA (in a combined bundle) and the placeholder-free
// env reach the child.
//
// A source var that is unset or empty is skipped silently: injection is opt-in
// per credential, and the common case (e.g. the claude profile for an OAuth
// user) is that the key is simply not present.
func resolveInject(plan *SandboxPlan, cfg *config.Config) error {
	specs, err := parseInjectHeader(cfg.InjectHeader)
	if err != nil {
		return err
	}
	specs = activeInjectSpecs(specs, cfg)
	if len(specs) == 0 {
		return nil
	}
	domainMatcher := policy.NewDomainMatcher(plan.AllowedDomains)
	ipMatcher := policy.NewIPMatcher(plan.AllowedIPs)
	bindings := make(map[policy.InjectTarget][]proxy.Injection, len(specs))
	for _, s := range specs {
		placeholder := injectPlaceholder(s.envVar)
		for _, t := range s.targets {
			if err := authorizeInjectTarget(t, domainMatcher, ipMatcher); err != nil {
				return err
			}
			bindings[t] = append(bindings[t], proxy.Injection{Placeholder: placeholder, Value: s.token})
		}
		// Set the source var to its placeholder: the sandbox sees only that.
		// EnvSet wins over passthrough in ResolveEnv, so the real value cannot
		// leak in even under --env '*'.
		plan.EnvSet[s.envVar] = placeholder
	}
	// Authorization above already produced the specific "add --domains/--ips"
	// error for an unlisted destination; reaching here without the proxy means
	// the destinations are allowed but unfiltered (e.g. --unrestricted-net).
	if !plan.ProxyEnabled {
		return fmt.Errorf("credential injection requires the network proxy: allow the destination with --domains/--ips and do not use --unrestricted-net"+injectEnvHint, injectEnvFlags(specs))
	}
	ca, err := proxy.NewCA()
	if err != nil {
		return fmt.Errorf("generating per-run CA: %w", err)
	}
	plan.CA = ca
	plan.InjectBindings = bindings

	// Trust-store delivery: each standard CA env var receives a bundle that
	// extends its existing value, or system roots when unset. The CA validates
	// only inside this run, so it is not sensitive to the action. Vars sharing
	// a base (usually all of them, unset and falling back to system roots)
	// share one written bundle.
	bundles := map[string]string{} // base -> written bundle path
	for _, k := range caBundleEnvKeys {
		base := plan.caBundleBase(k)
		bundle, ok := bundles[base]
		if !ok {
			bundle, err = writeCABundleFile(plan.TempDir, caBundleFilename(k), base, ca.CertPEM())
			if err != nil {
				return err
			}
			bundles[base] = bundle
			plan.ROFiles = appendUniq(plan.ROFiles, bundle)
		}
		plan.EnvSet[k] = bundle
	}
	return nil
}

var caBundleEnvKeys = []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"}

func (p *SandboxPlan) caBundleBase(name string) string {
	// An explicitly set value wins over passthrough, as in ResolveEnv — an
	// explicit empty (--env SSL_CERT_FILE=) means system roots, not the host
	// value.
	base, explicit := p.EnvSet[name]
	if !explicit && p.envPassesThrough(name) {
		base = os.Getenv(name)
	}
	if base == "" {
		return ""
	}
	// Some vars may legitimately point at a directory of certificates (e.g.
	// REQUESTS_CA_BUNDLE), which cannot be extended by concatenation.
	if fi, err := os.Stat(base); err == nil && fi.IsDir() {
		clog.Warnf("%s points at a directory (%s), which cannot be extended with the per-run CA; using the system CA bundle as its base instead", name, base)
		return ""
	}
	return base
}

func caBundleFilename(name string) string {
	if name == "SSL_CERT_FILE" {
		return "ca-bundle.pem"
	}
	return "ca-bundle-" + strings.ToLower(name) + ".pem"
}

// writeCABundleFile writes a PEM bundle of the base roots plus the per-run CA
// to the temp dir and returns its path. Base is the trust store to extend;
// when empty it falls back to the system roots.
// It fails if the base roots cannot be located or read: this bundle replaces
// the sandbox's TLS trust (SSL_CERT_FILE etc.), so a bundle holding only the
// per-run CA would break trust for every HTTPS destination other than the
// injected hosts.
func writeCABundleFile(tmpDir, filename, base string, caPEM []byte) (string, error) {
	if base == "" {
		base = systemCABundle()
	}
	if base == "" {
		return "", fmt.Errorf("credential injection: no system CA bundle found; cannot deliver TLS trust to the sandbox without overriding it")
	}
	buf, err := os.ReadFile(base)
	if err != nil {
		return "", fmt.Errorf("credential injection: reading CA bundle %s: %w", base, err)
	}
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	buf = append(buf, caPEM...)
	path := filepath.Join(tmpDir, filename)
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		return "", fmt.Errorf("writing CA bundle: %w", err)
	}
	return path, nil
}

// systemCABundle returns the first system CA bundle found, or "".
func systemCABundle() string {
	for _, p := range []string{
		"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Alpine
		"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora, RHEL
		"/etc/ssl/ca-bundle.pem",                            // openSUSE
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
		"/etc/ssl/cert.pem",                                 // macOS, some BSDs
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
