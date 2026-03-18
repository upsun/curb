//go:build !linux && !darwin

package sandbox

import "github.com/upsun/curb/config"

// degradedPlanBuilder implements PlanBuilder as a fallback for platforms
// without kernel sandbox support. Only environment sanitization is applied.
type degradedPlanBuilder struct{}

func newPlanBuilder() PlanBuilder { return degradedPlanBuilder{} }

func (degradedPlanBuilder) BuildPlan(cfg *config.Config, caps *Capabilities) (*SandboxPlan, error) {
	return buildDegradedPlan(cfg, caps)
}
