package sandbox

import (
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/upsun/curb/clog"
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
	ROFiles        []string
	RWPaths        []string
	RWFiles        []string
	HiddenPaths    []string
	ExecPaths      []string
	NetEnabled     bool
	AllowedDomains []string
	AllowLocalhost bool
	ECHMode        string
	RequireSNI     bool
	AllowHTTP      bool
	EnvSet         map[string]string
	EnvPassthrough []string
	DegradedLayers []DegradedLayer
	TempDir      string
	NoFSRestrict bool
	Quiet        bool
	Command        []string
	Caps           *Capabilities
	Logger         *clog.Logger
}

// ChildConfig is the serializable config sent from parent to child over a pipe.
type ChildConfig struct {
	Command        []string `json:"command"`
	Env            []string `json:"env"`
	ROPaths        []string `json:"ro_paths,omitempty"`
	ROFiles        []string `json:"ro_files,omitempty"`
	RWPaths        []string `json:"rw_paths,omitempty"`
	RWFiles        []string `json:"rw_files,omitempty"`
	HiddenPaths    []string `json:"hidden_paths,omitempty"`
	ExecPaths      []string `json:"exec_paths,omitempty"`
	NoFSRestrict   bool     `json:"no_fs_restrict,omitempty"`
	NetEnabled     bool     `json:"net_enabled"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	Quiet   bool   `json:"quiet,omitempty"`
	TempDir string `json:"temp_dir"`
}

// BuildPlan resolves the sandbox enforcement plan from config and capabilities.
// It returns an error only for fatal conditions (user ns unavailable, net required but missing).
func BuildPlan(cfg *config.Config, caps *Capabilities) (*SandboxPlan, error) {
	if runtime.GOOS != "linux" {
		// Non-Linux: env-only mode. Record all layers as degraded.
		return buildDegradedPlan(cfg, caps)
	}

	if caps.UserNS != nil {
		return nil, fmt.Errorf("fatal: %w\n\n%s", caps.UserNS, userNSFixMessage())
	}

	if len(cfg.AllowedDomains) > 0 || cfg.AllowLocalhost {
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
	if caps.LandlockABI == 0 {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "landlock",
			Reason: "not available (requires kernel 5.13+)",
			Impact: landlockWarnMessage(),
		})
	}

	plan.Quiet = cfg.Quiet

	// Resolve the real home dir for tilde expansion (before child overrides HOME).
	realHome, _ := os.UserHomeDir()

	// Filesystem policy.
	plan.NoFSRestrict = cfg.NoFSRestrict
	if cfg.NoFSRestrict {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "filesystem",
			Reason: "--allow-write '*'",
			Impact: "Filesystem restrictions disabled by user.",
		})
	} else {
		// Expand tildes and globs in user-supplied paths, then prepend defaults.
		userRO := slices.Clone(cfg.ROPaths)
		plan.HiddenPaths = slices.Clone(cfg.HiddenPaths)
		if len(plan.HiddenPaths) > 0 && caps.MountNS != nil {
			return nil, fmt.Errorf("--hide requires mount namespaces: %w", caps.MountNS)
		}
		if realHome != "" {
			userRO = config.ExpandTildes(userRO, realHome)
			if len(plan.HiddenPaths) > 0 {
				plan.HiddenPaths = config.ExpandTildes(plan.HiddenPaths, realHome)
			}
		}
		userRO = config.ExpandGlobs(userRO)
		plan.HiddenPaths = config.ExpandGlobs(plan.HiddenPaths)
		plan.ROPaths = slices.Concat(config.DefaultROPaths, userRO)
		plan.ROFiles = append(plan.ROFiles, config.DefaultROFiles...)
		plan.RWPaths = append(plan.RWPaths, config.DefaultRWPaths...)
		plan.RWFiles = append(plan.RWFiles, config.DefaultRWFiles...)
	}
	plan.RWPaths = append(plan.RWPaths, cfg.RWPaths...)
	if realHome != "" {
		plan.RWPaths = config.ExpandTildes(plan.RWPaths, realHome)
	}
	plan.RWPaths = config.ExpandGlobs(plan.RWPaths)

	// CWD: always read-only by default (use --allow-write . for write access).
	cwd, err := os.Getwd()
	if err == nil && !cfg.NoFSRestrict {
		plan.ROPaths = append(plan.ROPaths, cwd)
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
			Reason: "--allow-exec '*'",
			Impact: "Executable restrictions disabled by user.",
		})
	} else {
		plan.ExecPaths = append(plan.ExecPaths, config.SystemExecPaths...)
		for _, name := range cfg.ExecAllow {
			if filepath.IsAbs(name) {
				// Expand globs in absolute exec paths (e.g. /usr/bin/python*).
				plan.ExecPaths = append(plan.ExecPaths, config.ExpandGlobs([]string{name})...)
			} else if abs, lookErr := exec.LookPath(name); lookErr == nil {
				plan.ExecPaths = append(plan.ExecPaths, abs)
			} else {
				return nil, fmt.Errorf("--allow-exec %s: not found in PATH", name)
			}
		}
		if len(cfg.Command) > 0 {
			cmd0 := cfg.Command[0]
			if filepath.IsAbs(cmd0) {
				plan.ExecPaths = append(plan.ExecPaths, cmd0)
			} else if abs, lookErr := exec.LookPath(cmd0); lookErr == nil {
				plan.ExecPaths = append(plan.ExecPaths, abs)
			}
		}

		// Resolve symlinks in exec paths so Landlock covers the target
		// inodes. Without this, symlinked binaries (e.g. ~/.local/bin/foo
		// -> ~/.local/share/foo/binary) fail with permission denied.
		plan.ExecPaths = resolveExecSymlinks(plan.ExecPaths)

		// Ensure directories containing exec paths are readable so the
		// child can stat() them for path resolution after Landlock.
		if !cfg.NoFSRestrict {
			plan.ROPaths = appendExecDirs(plan.ROPaths, plan.ExecPaths)
		}
	}

	// Network policy.
	plan.NetEnabled = len(cfg.AllowedDomains) > 0 || cfg.AllowLocalhost
	if plan.NetEnabled && !cfg.NoFSRestrict {
		// Ensure /etc/resolv.conf's real path is readable for DNS resolution.
		// On systemd systems, /etc/resolv.conf is a symlink to /run/systemd/resolve/,
		// which Landlock would otherwise block.
		if dir := resolvConfDir(); dir != "" {
			plan.ROPaths = append(plan.ROPaths, dir)
		}
	}
	plan.AllowedDomains = cfg.AllowedDomains
	plan.AllowLocalhost = cfg.AllowLocalhost
	plan.ECHMode = cfg.ECHMode
	plan.RequireSNI = cfg.RequireSNI
	plan.AllowHTTP = cfg.AllowHTTP

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
		Env:            p.ResolveEnv(),
		ROPaths:        p.ROPaths,
		ROFiles:        p.ROFiles,
		RWPaths:        p.RWPaths,
		RWFiles:        p.RWFiles,
		HiddenPaths:    p.HiddenPaths,
		ExecPaths:      p.ExecPaths,
		NoFSRestrict:   p.NoFSRestrict,
		NetEnabled:     p.NetEnabled,
		AllowedDomains: p.AllowedDomains,
		Quiet:   p.Quiet,
		TempDir: p.TempDir,
	}
}

// isInternalEnvVar reports whether name is a curb-internal environment variable
// that must never leak into the sandboxed process.
func isInternalEnvVar(name string) bool {
	return strings.HasPrefix(name, "_CURB_")
}

// ResolveEnv resolves the final environment from EnvSet and EnvPassthrough.
func (p *SandboxPlan) ResolveEnv() []string {
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
		pr("    read-write: %s\n", strings.Join(p.RWPaths, " "))
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
	} else if p.NetEnabled && p.AllowLocalhost {
		ln("    allowed:    localhost only (non-loopback traffic dropped)")
	} else if p.NetEnabled {
		ln("    allowed:    none")
	} else {
		ln("    allowed:    none (no network interface)")
	}
	if p.AllowLocalhost {
		ln("    localhost:  forwarded to host")
	}
	if p.NetEnabled && len(p.AllowedDomains) > 0 {
		pr("    tls (443):  SNI filtered, ECH %s", p.ECHMode)
		if p.RequireSNI {
			pr(", SNI required")
		}
		pr("\n")
		if p.AllowHTTP {
			ln("    http (80):  Host filtered")
		} else {
			ln("    http (80):  blocked (use --allow-http to enable)")
		}
		ln("    other:      dropped")
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

// appendExecDirs adds parent directories of exec paths to roPaths, skipping
// directories that are already covered by an existing RO path prefix.
func appendExecDirs(roPaths, execPaths []string) []string {
	seen := make(map[string]bool, len(roPaths))
	for _, p := range roPaths {
		seen[p] = true
	}
	for _, p := range execPaths {
		dir := filepath.Dir(p)
		if dir == "/" || seen[dir] {
			continue
		}
		// Skip if already covered by a parent RO path.
		covered := false
		for _, ro := range roPaths {
			if strings.HasPrefix(dir, ro+"/") || dir == ro {
				covered = true
				break
			}
		}
		if !covered {
			roPaths = append(roPaths, dir)
			seen[dir] = true
		}
	}
	return roPaths
}

// resolveExecSymlinks evaluates symlinks in exec paths and appends any resolved
// paths that differ from the original, so Landlock covers both the symlink and
// its target. Errors are silently ignored (the path may not exist yet).
func resolveExecSymlinks(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		seen[p] = true
	}
	for _, p := range paths {
		resolved, err := filepath.EvalSymlinks(p)
		if err == nil && !seen[resolved] {
			paths = append(paths, resolved)
			seen[resolved] = true
		}
	}
	return paths
}

// resolvConfDir returns the parent directory of /etc/resolv.conf's real path,
// or "" if it's already under /etc or can't be resolved.
func resolvConfDir() string {
	real, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	dir := filepath.Dir(real)
	if strings.HasPrefix(dir, "/etc") {
		return "" // Already covered by default RO paths.
	}
	return dir
}

// buildDegradedPlan creates a plan for non-Linux platforms where only
// environment sanitization is available.
func buildDegradedPlan(cfg *config.Config, caps *Capabilities) (*SandboxPlan, error) {
	plan := &SandboxPlan{Caps: caps}

	if len(cfg.AllowedDomains) > 0 || cfg.AllowLocalhost {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "network filtering",
			Reason: fmt.Sprintf("not supported on %s", runtime.GOOS),
			Impact: "Network filtering is not available; all network access is unrestricted.",
		})
	}
	if !cfg.NoFSRestrict {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "filesystem restrictions",
			Reason: fmt.Sprintf("not supported on %s", runtime.GOOS),
			Impact: "Filesystem restrictions are not available; all paths are accessible.",
		})
	}
	if !cfg.NoExecRestrict {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "executable control",
			Reason: fmt.Sprintf("not supported on %s", runtime.GOOS),
			Impact: "Executable control is not available; all binaries can be executed.",
		})
	}

	// Temp directory.
	tmpDir, err := os.MkdirTemp("", "curb-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	plan.TempDir = tmpDir

	// Environment policy (still enforced on all platforms).
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
