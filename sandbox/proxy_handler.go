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

// buildProxyHandler creates the HTTP proxy handler from the sandbox plan.
func buildProxyHandler(plan *SandboxPlan) *proxy.Handler {
	h := &proxy.Handler{FilterBase: buildFilterBase(plan)}
	if plan.CA != nil && len(plan.InjectBindings) > 0 {
		inj := proxy.NewInjector(plan.CA)
		for host, injections := range plan.InjectBindings {
			for _, injection := range injections {
				inj.Bind(host, injection)
			}
		}
		h.Injector = inj
	}
	return h
}

// buildSOCKS5Server creates the SOCKS5 proxy server from the sandbox plan.
func buildSOCKS5Server(plan *SandboxPlan) *proxy.SOCKS5Server {
	return &proxy.SOCKS5Server{
		FilterBase: buildFilterBase(plan),
	}
}
