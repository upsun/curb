package sandbox

import (
	"github.com/upsun/curb/policy"
	"github.com/upsun/curb/proxy"
)

// buildFilterBase creates the shared filtering config from the sandbox plan.
func buildFilterBase(plan *SandboxPlan) proxy.FilterBase {
	fb := proxy.FilterBase{Logger: plan.Logger}
	if len(plan.AllowedDomains) > 0 {
		matcher := policy.NewDomainMatcher(plan.AllowedDomains)
		fb.DomainCheck = matcher.Match
	}
	if len(plan.AllowedIPs) > 0 {
		ipMatcher := policy.NewIPMatcher(plan.AllowedIPs)
		fb.IPCheck = ipMatcher.Match
	}
	return fb
}

// buildInjector creates the credential injector from the plan, or nil when no
// bindings are configured. It is shared by the HTTP and SOCKS5 proxies so both
// egress paths inject for bound hosts.
func buildInjector(plan *SandboxPlan) *proxy.Injector {
	if plan.CA == nil || len(plan.InjectBindings) == 0 {
		return nil
	}
	inj := proxy.NewInjector(plan.CA)
	for target, injections := range plan.InjectBindings {
		for _, injection := range injections {
			inj.Bind(target.Host, target.Port, injection)
		}
	}
	return inj
}

// buildProxyHandler creates the HTTP proxy handler from the sandbox plan.
func buildProxyHandler(plan *SandboxPlan) *proxy.Handler {
	return &proxy.Handler{FilterBase: buildFilterBase(plan), Injector: buildInjector(plan)}
}

// buildSOCKS5Server creates the SOCKS5 proxy server from the sandbox plan.
func buildSOCKS5Server(plan *SandboxPlan) *proxy.SOCKS5Server {
	return &proxy.SOCKS5Server{
		FilterBase: buildFilterBase(plan),
		Injector:   buildInjector(plan),
	}
}
