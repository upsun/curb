package sandbox

import (
	"github.com/upsun/curb/policy"
	"github.com/upsun/curb/proxy"
)

// buildProxyHandler creates the MITM proxy handler from the sandbox plan.
func buildProxyHandler(plan *SandboxPlan) *proxy.Handler {
	h := &proxy.Handler{
		CertCache: proxy.NewCertCache(plan.CA),
		Logger:    plan.Logger,
		AllowHTTP: plan.AllowHTTP,
	}
	if len(plan.AllowedDomains) > 0 {
		matcher := policy.NewDomainMatcher(plan.AllowedDomains)
		h.DomainCheck = matcher.Match
	}
	if len(plan.AllowedIPs) > 0 {
		ipMatcher := policy.NewIPMatcher(plan.AllowedIPs)
		h.IPCheck = ipMatcher.Match
	}
	return h
}
