//go:build linux

package sandbox

import "github.com/upsun/curb/config"

// linuxPlanBuilder implements PlanBuilder using Linux namespaces, pivot_root,
// Landlock, seccomp, and the MITM proxy / netstack for network filtering.
type linuxPlanBuilder struct{}

func newPlanBuilder() PlanBuilder { return linuxPlanBuilder{} }

func (linuxPlanBuilder) BuildPlan(cfg *config.Config, caps *Capabilities) (*SandboxPlan, error) {
	plan := &SandboxPlan{Caps: caps, Quiet: cfg.Quiet}
	var removals planRemovals

	// Create tmpDir first — needed for sandbox HOME fallback.
	tmpDir, err := createTempDir()
	if err != nil {
		return nil, err
	}
	plan.TempDir = tmpDir

	// Determine sandbox HOME before tilde expansion.
	sandboxHome := resolveSandboxHome(cfg, tmpDir)
	plan.SandboxHome = sandboxHome
	warnTildeToTmpDir(cfg, sandboxHome, tmpDir)

	if err := resolveCapabilities(plan, cfg, caps); err != nil {
		return nil, err
	}
	if err := resolveFilesystem(plan, cfg, &removals, sandboxHome); err != nil {
		return nil, err
	}
	if err := resolveExec(plan, cfg, &removals, sandboxHome); err != nil {
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
