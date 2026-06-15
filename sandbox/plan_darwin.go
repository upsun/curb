//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/upsun/curb/clog"
	"github.com/upsun/curb/config"
)

// darwinPlanBuilder implements PlanBuilder for macOS Seatbelt.
type darwinPlanBuilder struct{}

func newPlanBuilder() PlanBuilder { return darwinPlanBuilder{} }

// BuildPlan resolves the sandbox plan for macOS using Seatbelt enforcement.
// It reuses the same resolve* helpers as Linux but sets UseSeatbelt instead of
// pivot_root/Landlock. All paths are canonicalized to resolve macOS symlinks
// (e.g. /var -> /private/var, /etc -> /private/etc, /tmp -> /private/tmp).
func (darwinPlanBuilder) BuildPlan(cfg *config.Config, caps *Capabilities, logger *clog.Logger) (*SandboxPlan, error) {
	if caps.Seatbelt != nil {
		return nil, fmt.Errorf("fatal: sandbox-exec is required on macOS: %w", caps.Seatbelt)
	}
	if len(cfg.InjectBearer) > 0 || len(cfg.InjectHeader) > 0 {
		return nil, fmt.Errorf("credential injection (--inject-bearer/--inject-header) is only supported on Linux")
	}

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

	hasFiltering := (len(cfg.AllowedDomains) > 0 || len(cfg.AllowedIPs) > 0) && !cfg.UnrestrictedNet
	plan.ProxyEnabled = hasFiltering

	// Seatbelt enforcement.
	plan.UseSeatbelt = true

	// Reuse the generic resolve helpers.
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

	// Allow the terminfo entry for $TERM so pagers (less, more) and
	// curses-based tools can detect terminal capabilities. Terminal
	// emulators like Ghostty, Kitty, and Alacritty ship their terminfo
	// under /Applications/<name>.app/ which is outside the default paths.
	addTerminfo(plan)
	if err := writeSkill(plan, plan.TempDir); err != nil {
		return nil, err
	}
	return plan, nil
}

// addTerminfo allows reading terminfo directories so pagers (less, more) can
// detect terminal capabilities. Checks $TERMINFO and $TERMINFO_DIRS; the
// system default (/usr/share/terminfo under /usr) is already accessible.
func addTerminfo(plan *SandboxPlan) {
	var dirs []string
	if ti := os.Getenv("TERMINFO"); ti != "" {
		dirs = append(dirs, ti)
	}
	if tiDirs := os.Getenv("TERMINFO_DIRS"); tiDirs != "" {
		dirs = append(dirs, filepath.SplitList(tiDirs)...)
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		root := canonicalize(d)
		if !isCoveredBySubpath(root, plan.ROPaths) {
			plan.ROPaths = append(plan.ROPaths, root)
		}
	}
}

// isCoveredBySubpath reports whether path is equal to or under any entry in paths.
func isCoveredBySubpath(path string, paths []string) bool {
	for _, p := range paths {
		if rel, err := filepath.Rel(p, path); err == nil && filepath.IsLocal(rel) {
			return true
		}
	}
	return false
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
