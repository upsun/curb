//go:build linux

package sandbox

import (
	"os"

	"github.com/upsun/curb/config"
)

// linuxPlanBuilder implements PlanBuilder using Linux namespaces, pivot_root,
// Landlock, seccomp, and the MITM proxy / netstack for network filtering.
type linuxPlanBuilder struct{}

func newPlanBuilder() PlanBuilder { return linuxPlanBuilder{} }

func (linuxPlanBuilder) BuildPlan(cfg *config.Config, caps *Capabilities) (*SandboxPlan, error) {
	plan := &SandboxPlan{Caps: caps, Quiet: cfg.Quiet}
	realHome, _ := os.UserHomeDir()
	var removals planRemovals
	if err := resolveCapabilities(plan, cfg, caps); err != nil {
		return nil, err
	}
	if err := resolveFilesystem(plan, cfg, &removals, realHome); err != nil {
		return nil, err
	}
	if err := resolveExec(plan, cfg, &removals, realHome); err != nil {
		return nil, err
	}
	resolveNetwork(plan, cfg)
	if err := resolveProxy(plan, cfg, caps); err != nil {
		return nil, err
	}
	if err := resolveEnv(plan, cfg); err != nil {
		return nil, err
	}
	resolveDenials(plan, &removals)
	return plan, nil
}
