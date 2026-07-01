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

	// ~ in path fields expands to the host HOME. Warn if the sandbox's
	// $HOME will differ from it, so paths under ~ won't align with the
	// sandboxed program's own $HOME.
	sandboxHome := resolveSandboxHome(cfg, tmpDir)
	plan.SandboxHome = sandboxHome
	hostHome := resolveHostHome()
	if err := checkHostHomeResolvable(cfg, hostHome); err != nil {
		return nil, err
	}
	warnHostHomePathMismatch(cfg, sandboxHome, hostHome)

	if err := resolveCapabilities(plan, cfg, caps); err != nil {
		return nil, err
	}
	if err := resolveFilesystem(plan, cfg, &removals, hostHome); err != nil {
		return nil, err
	}
	if err := resolveExec(plan, cfg, &removals, hostHome, logger); err != nil {
		return nil, err
	}
	resolveNetwork(plan, cfg)
	if err := resolveProxy(plan); err != nil {
		return nil, err
	}
	if err := resolveEnv(plan, cfg); err != nil {
		return nil, err
	}
	if err := resolveInject(plan, cfg); err != nil {
		return nil, err
	}
	resolveDenials(plan, &removals)
	if err := writeSkill(plan, plan.TempDir); err != nil {
		return nil, err
	}
	return plan, nil
}
