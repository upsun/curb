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

// buildProxyHandler creates the MITM proxy handler from the sandbox plan.
func buildProxyHandler(plan *SandboxPlan) *proxy.Handler {
	return &proxy.Handler{
		FilterBase: buildFilterBase(plan),
		CertCache:  proxy.NewCertCache(plan.CA),
		AllowHTTP:  plan.AllowHTTP,
	}
}

// buildSOCKS5Server creates the SOCKS5 proxy server from the sandbox plan.
func buildSOCKS5Server(plan *SandboxPlan) *proxy.SOCKS5Server {
	return &proxy.SOCKS5Server{
		FilterBase: buildFilterBase(plan),
	}
}
