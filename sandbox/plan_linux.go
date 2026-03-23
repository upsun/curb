//go:build linux

package sandbox

import (
	"github.com/upsun/curb/clog"
	"github.com/upsun/curb/config"
)

// linuxPlanBuilder implements PlanBuilder using Linux namespaces, pivot_root,
// Landlock, seccomp, and an HTTP/SOCKS5 proxy for network filtering.
type linuxPlanBuilder struct{}

func newPlanBuilder() PlanBuilder { return linuxPlanBuilder{} }

func (linuxPlanBuilder) BuildPlan(cfg *config.Config, caps *Capabilities, logger *clog.Logger) (*SandboxPlan, error) {
	plan := &SandboxPlan{Caps: caps, Quiet: cfg.Quiet, Logger: logger}
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
	if err := resolveExec(plan, cfg, &removals, sandboxHome, logger); err != nil {
		return nil, err
	}
	resolveNetwork(plan, cfg)
	if err := resolveProxy(plan); err != nil {
		return nil, err
	}
	if err := resolveEnv(plan, cfg); err != nil {
		return nil, err
	}
	resolveDenials(plan, &removals)
	return plan, nil
}
