//go:build darwin

package sandbox

import (
	"fmt"
	"path/filepath"

	"github.com/upsun/curb/config"
)

// darwinPlanBuilder implements PlanBuilder for macOS Seatbelt.
type darwinPlanBuilder struct{}

func newPlanBuilder() PlanBuilder { return darwinPlanBuilder{} }

// BuildPlan resolves the sandbox plan for macOS using Seatbelt enforcement.
// It reuses the same resolve* helpers as Linux but sets UseSeatbelt instead of
// pivot_root/Landlock. All paths are canonicalized to resolve macOS symlinks
// (e.g. /var -> /private/var, /etc -> /private/etc, /tmp -> /private/tmp).
func (darwinPlanBuilder) BuildPlan(cfg *config.Config, caps *Capabilities) (*SandboxPlan, error) {
	if caps.Seatbelt != nil {
		return nil, fmt.Errorf("fatal: sandbox-exec is required on macOS: %w", caps.Seatbelt)
	}

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

	hasFiltering := (len(cfg.AllowedDomains) > 0 || len(cfg.AllowedIPs) > 0) && !cfg.UnrestrictedNet
	plan.ProxyEnabled = hasFiltering

	// Seatbelt enforcement.
	plan.UseSeatbelt = true

	// Reuse the generic resolve helpers.
	if err := resolveFilesystem(plan, cfg, &removals, sandboxHome); err != nil {
		return nil, err
	}
	if err := resolveExec(plan, cfg, &removals, sandboxHome); err != nil {
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

	// Seatbelt-specific: system.sb (imported in generateSBPL) grants read
	// access to several default system paths including /private/etc/passwd,
	// /private/etc/group, /usr/lib, /usr/share, etc. Simply removing a path
	// from our allow list is not enough — we must emit an explicit (deny ...)
	// rule so that system.sb's allow cannot be inherited.
	// Add all explicitly excluded paths as deny rules (deduplicating with any
	// already added by resolveDenials via subpathDenials).
	plan.HiddenPaths = appendUnique(plan.HiddenPaths, absPaths(removals.roRemoves)...)
	plan.DenyWritePaths = appendUnique(plan.DenyWritePaths, absPaths(removals.rwRemoves)...)
	plan.DenyExecPaths = appendUnique(plan.DenyExecPaths, absPaths(removals.execRemoves)...)

	// Canonicalize all paths to resolve macOS symlinks.
	plan.ROPaths = canonicalizePaths(plan.ROPaths)
	plan.ROFiles = canonicalizePaths(plan.ROFiles)
	plan.RWPaths = canonicalizePaths(plan.RWPaths)
	plan.RWFiles = canonicalizePaths(plan.RWFiles)
	plan.ExecPaths = canonicalizePaths(plan.ExecPaths)
	plan.HiddenPaths = canonicalizePaths(plan.HiddenPaths)
	plan.DenyWritePaths = canonicalizePaths(plan.DenyWritePaths)
	plan.DenyExecPaths = canonicalizePaths(plan.DenyExecPaths)

	return plan, nil
}

// canonicalizePaths resolves symlinks in each path and deduplicates.
// This is critical on macOS where /var -> /private/var, /etc -> /private/etc,
// /tmp -> /private/tmp, etc.
func canonicalizePaths(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	var result []string
	for _, p := range paths {
		canonical := canonicalize(p)
		if !seen[canonical] {
			seen[canonical] = true
			result = append(result, canonical)
		}
	}
	return result
}

// absPaths converts paths to absolute form, silently dropping ones that fail.
func absPaths(paths []string) []string {
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err == nil {
			result = append(result, abs)
		}
	}
	return result
}

// appendUnique appends items to dst, skipping any already present.
func appendUnique(dst []string, items ...string) []string {
	seen := make(map[string]bool, len(dst))
	for _, p := range dst {
		seen[p] = true
	}
	for _, p := range items {
		if !seen[p] {
			seen[p] = true
			dst = append(dst, p)
		}
	}
	return dst
}

// canonicalize resolves symlinks in path, falling back to the original on error.
func canonicalize(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}
