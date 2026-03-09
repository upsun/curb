package sandbox

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/platformsh/curb/config"
)

// DegradedLayer records a sandbox layer that cannot be fully enforced.
type DegradedLayer struct {
	Layer  string
	Reason string
	Impact string
}

// SandboxPlan is the resolved enforcement plan derived from Config + Capabilities.
type SandboxPlan struct {
	ROPaths        []string
	RWPaths        []string
	HiddenPaths    []string
	ExecPaths      []string
	NetEnabled     bool
	AllowedDomains []string
	EnvSet         map[string]string
	EnvPassthrough []string
	DegradedLayers []DegradedLayer
	TempDir        string
	CWDWritable    bool
	Caps           *Capabilities
}

// BuildPlan resolves the sandbox enforcement plan from config and capabilities.
// It returns an error only for fatal conditions (user ns unavailable, net required but missing).
func BuildPlan(cfg *config.Config, caps *Capabilities) (*SandboxPlan, error) {
	if caps.UserNS != nil {
		return nil, fmt.Errorf("fatal: %w\n\n%s", caps.UserNS, userNSFixMessage())
	}

	if len(cfg.AllowedDomains) > 0 || cfg.AllowFile != "" {
		if caps.NetNS != nil {
			return nil, fmt.Errorf("fatal: %w\n\n%s", caps.NetNS, netNSFixMessage())
		}
		if caps.TUN != nil {
			return nil, fmt.Errorf("fatal: %w\n\n%s", caps.TUN, tunFixMessage())
		}
	}

	plan := &SandboxPlan{
		Caps: caps,
	}

	// Record degraded layers.
	if caps.MountNS != nil {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "mount namespace",
			Reason: caps.MountNS.Error(),
			Impact: mountNSWarnMessage(),
		})
	}
	if caps.LandlockABI == 0 {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "landlock",
			Reason: "not available (requires kernel 5.13+)",
			Impact: "Filesystem restrictions use mount namespace and seccomp-bpf only (weaker).",
		})
	}

	// Filesystem policy.
	if cfg.NoFSRestrict {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "filesystem",
			Reason: "--no-fs-restrict",
			Impact: "Filesystem restrictions disabled by user.",
		})
	} else {
		plan.ROPaths = append(config.DefaultROPaths[:0:0], config.DefaultROPaths...)
		plan.ROPaths = append(plan.ROPaths, cfg.ROPaths...)
		plan.HiddenPaths = append(config.DefaultHiddenPaths[:0:0], config.DefaultHiddenPaths...)
		plan.HiddenPaths = append(plan.HiddenPaths, cfg.HiddenPaths...)
	}
	plan.RWPaths = append(plan.RWPaths, cfg.RWPaths...)

	// CWD Git detection.
	cwd, err := os.Getwd()
	if err == nil {
		isGit, gitErr := config.IsGitWorkTree(cwd)
		if gitErr == nil && isGit {
			plan.CWDWritable = true
			plan.RWPaths = append(plan.RWPaths, cwd)
		}
	}

	// Temp directory.
	tmpDir, err := os.MkdirTemp("", "curb-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	plan.TempDir = tmpDir
	plan.RWPaths = append(plan.RWPaths, tmpDir)

	// Exec policy.
	if cfg.NoExecRestrict {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "exec",
			Reason: "--no-exec-restrict",
			Impact: "Executable restrictions disabled by user.",
		})
	} else {
		plan.ExecPaths = append(plan.ExecPaths, config.SystemExecPaths...)
		for _, name := range cfg.ExecAllow {
			if filepath.IsAbs(name) {
				plan.ExecPaths = append(plan.ExecPaths, name)
			} else if abs, lookErr := exec.LookPath(name); lookErr == nil {
				plan.ExecPaths = append(plan.ExecPaths, abs)
			} else {
				plan.ExecPaths = append(plan.ExecPaths, name+" (not found)")
			}
		}
	}

	// Network policy.
	plan.NetEnabled = len(cfg.AllowedDomains) > 0 || cfg.AllowFile != ""
	plan.AllowedDomains = cfg.AllowedDomains

	// Environment policy.
	plan.EnvSet = map[string]string{
		"HOME":   cfg.HomePath,
		"TMPDIR": tmpDir,
		"PATH":   strings.Join(config.SystemExecPaths, ":"),
		"SHELL":  "/bin/sh",
	}
	if plan.EnvSet["HOME"] == "" {
		plan.EnvSet["HOME"] = tmpDir
	}
	for _, pair := range cfg.EnvSet {
		k, v, _ := strings.Cut(pair, "=")
		plan.EnvSet[k] = v
	}

	if cfg.EnvPassthroughAll {
		plan.EnvPassthrough = []string{"(all)"}
	} else {
		plan.EnvPassthrough = append(plan.EnvPassthrough, config.SafePassthroughVars...)
		plan.EnvPassthrough = append(plan.EnvPassthrough, cfg.EnvPassthrough...)
	}

	return plan, nil
}

// Cleanup removes temporary resources created by BuildPlan.
func (p *SandboxPlan) Cleanup() {
	if p.TempDir != "" {
		_ = os.RemoveAll(p.TempDir)
	}
}

// PrintDryRun writes a human-readable sandbox plan to w.
func (p *SandboxPlan) PrintDryRun(w io.Writer) {
	pr := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }
	ln := func(a ...any) { _, _ = fmt.Fprintln(w, a...) }

	ln("curb: system capabilities")
	printCap(w, "user namespaces", p.Caps.UserNS, p.capUserInfo())
	printCap(w, "mount namespaces", p.Caps.MountNS, "")
	printCap(w, "network namespaces", p.Caps.NetNS, "")
	printCap(w, "/dev/net/tun", p.Caps.TUN, "")
	printLandlock(w, p.Caps.LandlockABI)
	ln()

	ln("curb: sandbox plan")

	// Filesystem.
	ln("  filesystem:")
	if len(p.ROPaths) > 0 {
		pr("    read-only:  %s\n", strings.Join(p.ROPaths, " "))
	}
	if len(p.RWPaths) > 0 {
		rw := make([]string, len(p.RWPaths))
		copy(rw, p.RWPaths)
		for i, path := range rw {
			cwd, _ := os.Getwd()
			if path == cwd && p.CWDWritable {
				rw[i] = ". (Git working tree detected)"
			}
		}
		pr("    read-write: %s\n", strings.Join(rw, " "))
	}
	if len(p.HiddenPaths) > 0 {
		pr("    hidden:     %s\n", strings.Join(p.HiddenPaths, " "))
	}
	if len(p.ExecPaths) > 0 {
		pr("    exec:       %s\n", strings.Join(p.ExecPaths, " "))
	}

	// Network.
	ln("  network:")
	if p.NetEnabled && len(p.AllowedDomains) > 0 {
		pr("    allowed:    %s\n", strings.Join(p.AllowedDomains, " "))
	} else if p.NetEnabled {
		ln("    allowed:    (from file)")
	} else {
		ln("    allowed:    none (no network interface)")
	}
	ln("    blocked:    everything else")

	// Environment.
	ln("  environment:")
	var setParts []string
	for k, v := range p.EnvSet {
		setParts = append(setParts, k+"="+v)
	}
	if len(setParts) > 0 {
		pr("    set:        %s\n", strings.Join(setParts, " "))
	}
	if len(p.EnvPassthrough) > 0 {
		pr("    passthrough: %s\n", strings.Join(p.EnvPassthrough, " "))
	}
	ln("    blocked:    everything else")

	// Enforcement level.
	if len(p.DegradedLayers) > 0 {
		ln("  enforcement: degraded")
		for _, d := range p.DegradedLayers {
			pr("    warning: %s: %s\n", d.Layer, d.Impact)
		}
	} else {
		ln("  enforcement: full")
	}
}

func (p *SandboxPlan) capUserInfo() string {
	if p.Caps.KernelInfo != "" {
		return "kernel " + p.Caps.KernelInfo
	}
	return ""
}

func printCap(w io.Writer, name string, err error, info string) {
	label := fmt.Sprintf("  %-20s", name+":")
	if err == nil {
		if info != "" {
			_, _ = fmt.Fprintf(w, "%sok (%s)\n", label, info)
		} else {
			_, _ = fmt.Fprintf(w, "%sok\n", label)
		}
	} else {
		_, _ = fmt.Fprintf(w, "%sunavailable (%s)\n", label, err)
	}
}

func printLandlock(w io.Writer, abi int) {
	label := fmt.Sprintf("  %-20s", "landlock:")
	if abi > 0 {
		_, _ = fmt.Fprintf(w, "%sok (ABI v%d)\n", label, abi)
	} else {
		_, _ = fmt.Fprintf(w, "%sunavailable\n", label)
	}
}
