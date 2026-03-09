package sandbox

import (
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/upsun/curb/config"
)

const (
	// InitEnvKey is the environment variable that triggers child init mode.
	InitEnvKey = "_CURB_INIT"

	// ExitSetupFailure is the exit code for curb's own setup failures.
	ExitSetupFailure = 111

	// childConfigFD is the fd for the config pipe in the child (ExtraFiles[0]).
	childConfigFD = 3

	// childSocketFD is the fd for the socketpair in the child (ExtraFiles[1]).
	childSocketFD = 4

	// envPassthroughAll is the sentinel value indicating all env vars pass through.
	envPassthroughAll = "(all)"
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
	GitHooksPath   string
	NetEnabled     bool
	AllowedDomains []string
	EnvSet         map[string]string
	EnvPassthrough []string
	DegradedLayers []DegradedLayer
	TempDir        string
	CWD            string
	CWDWritable    bool
	NoFSRestrict   bool
	Command        []string
	Caps           *Capabilities
}

// ChildConfig is the serializable config sent from parent to child over a pipe.
type ChildConfig struct {
	Command        []string `json:"command"`
	Env            []string `json:"env"`
	ROPaths        []string `json:"ro_paths,omitempty"`
	RWPaths        []string `json:"rw_paths,omitempty"`
	HiddenPaths    []string `json:"hidden_paths,omitempty"`
	ExecPaths      []string `json:"exec_paths,omitempty"`
	GitHooksPath   string   `json:"git_hooks_path,omitempty"`
	NoFSRestrict   bool     `json:"no_fs_restrict,omitempty"`
	NetEnabled     bool     `json:"net_enabled"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	TempDir        string   `json:"temp_dir"`
	CWD            string   `json:"cwd,omitempty"`
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
			Impact: landlockWarnMessage(),
		})
	}

	// Resolve the real home dir for tilde expansion (before child overrides HOME).
	realHome, _ := os.UserHomeDir()

	// Filesystem policy.
	plan.NoFSRestrict = cfg.NoFSRestrict
	if cfg.NoFSRestrict {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "filesystem",
			Reason: "--no-fs-restrict",
			Impact: "Filesystem restrictions disabled by user.",
		})
	} else {
		plan.ROPaths = slices.Concat(config.DefaultROPaths, cfg.ROPaths)
		plan.HiddenPaths = slices.Concat(config.DefaultHiddenPaths, cfg.HiddenPaths)
		if realHome != "" {
			plan.ROPaths = config.ExpandTildes(plan.ROPaths, realHome)
			plan.HiddenPaths = config.ExpandTildes(plan.HiddenPaths, realHome)
		} else if hasTildePaths(plan.HiddenPaths) {
			plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
				Layer:  "filesystem",
				Reason: "$HOME not set",
				Impact: "Cannot expand ~/ paths; dotfile hiding may not work.",
			})
		}
	}
	plan.RWPaths = append(plan.RWPaths, cfg.RWPaths...)
	if realHome != "" {
		plan.RWPaths = config.ExpandTildes(plan.RWPaths, realHome)
	}

	// CWD Git detection.
	cwd, err := os.Getwd()
	if err == nil {
		plan.CWD = cwd
		gitRoot, gitErr := config.FindGitRoot(cwd)
		if gitErr == nil && gitRoot != "" {
			plan.CWDWritable = true
			plan.RWPaths = append(plan.RWPaths, cwd)
			if !cfg.NoFSRestrict {
				if hooksDir := config.FindGitHooksDir(gitRoot); hooksDir != "" {
					plan.GitHooksPath = hooksDir
				}
			}
		} else if !cfg.NoFSRestrict {
			// Non-Git directory: read-only CWD.
			plan.ROPaths = append(plan.ROPaths, cwd)
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
	plan.EnvSet = config.ForcedEnvVars(tmpDir, cfg.HomePath)
	for _, pair := range cfg.EnvSet {
		k, v, _ := strings.Cut(pair, "=")
		plan.EnvSet[k] = v
	}

	if cfg.EnvPassthroughAll {
		plan.EnvPassthrough = []string{envPassthroughAll}
	} else {
		plan.EnvPassthrough = append(plan.EnvPassthrough, config.SafePassthroughVars...)
		plan.EnvPassthrough = append(plan.EnvPassthrough, cfg.EnvPassthrough...)
	}

	plan.Command = cfg.Command

	return plan, nil
}

// childConfig builds the ChildConfig from the plan, resolving the environment.
func (p *SandboxPlan) childConfig() ChildConfig {
	return ChildConfig{
		Command:        p.Command,
		Env:            p.resolveEnv(),
		ROPaths:        p.ROPaths,
		RWPaths:        p.RWPaths,
		HiddenPaths:    p.HiddenPaths,
		ExecPaths:      p.ExecPaths,
		GitHooksPath:   p.GitHooksPath,
		NoFSRestrict:   p.NoFSRestrict,
		NetEnabled:     p.NetEnabled,
		AllowedDomains: p.AllowedDomains,
		TempDir:        p.TempDir,
		CWD:            p.CWD,
	}
}

// isInternalEnvVar reports whether name is a curb-internal environment variable
// that must never leak into the sandboxed process.
func isInternalEnvVar(name string) bool {
	return strings.HasPrefix(name, "_CURB_")
}

// resolveEnv resolves the final environment from EnvSet and EnvPassthrough.
func (p *SandboxPlan) resolveEnv() []string {
	env := make(map[string]string, len(p.EnvSet))
	maps.Copy(env, p.EnvSet)
	if len(p.EnvPassthrough) > 0 && p.EnvPassthrough[0] == envPassthroughAll {
		for _, e := range os.Environ() {
			k, v, _ := strings.Cut(e, "=")
			if isInternalEnvVar(k) {
				continue
			}
			if _, ok := env[k]; !ok {
				env[k] = v
			}
		}
	} else {
		for _, name := range p.EnvPassthrough {
			if isInternalEnvVar(name) {
				continue
			}
			if v, ok := os.LookupEnv(name); ok {
				if _, set := env[name]; !set {
					env[name] = v
				}
			}
		}
	}
	result := make([]string, 0, len(env))
	for k, v := range env {
		result = append(result, k+"="+v)
	}
	sort.Strings(result)
	return result
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
	if p.Caps.LandlockABI > 0 {
		printCap(w, "landlock", nil, fmt.Sprintf("ABI v%d", p.Caps.LandlockABI))
	} else {
		printCap(w, "landlock", fmt.Errorf("unavailable"), "")
	}
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
			if path == p.CWD && p.CWDWritable {
				rw[i] = ". (Git working tree detected)"
			}
		}
		pr("    read-write: %s\n", strings.Join(rw, " "))
	}
	if len(p.HiddenPaths) > 0 {
		pr("    hidden:     %s\n", strings.Join(p.HiddenPaths, " "))
	}
	if p.GitHooksPath != "" {
		pr("    hooks (ro): %s\n", p.GitHooksPath)
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
	keys := make([]string, 0, len(p.EnvSet))
	for k := range p.EnvSet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var setParts []string
	for _, k := range keys {
		setParts = append(setParts, k+"="+p.EnvSet[k])
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

func hasTildePaths(paths []string) bool {
	for _, p := range paths {
		if strings.HasPrefix(p, "~/") {
			return true
		}
	}
	return false
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
