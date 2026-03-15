package sandbox

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"math/rand/v2"
	"net"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/upsun/curb/clog"
	"github.com/upsun/curb/config"
	"github.com/upsun/curb/policy"
	"github.com/upsun/curb/proxy"
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

	// TestNoLandlockEnvKey disables Landlock in tests to exercise mount-NS-only path.
	TestNoLandlockEnvKey = "_CURB_TEST_NO_LANDLOCK"
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
	DenyWritePaths []string
	DenyExecPaths  []string
	ExecPaths      []string
	UsePivotRoot   bool
	UseLandlock    bool
	PidNS          bool
	NetEnabled      bool
	UnrestrictedNet bool
	AllowedDomains  []string
	AllowedIPs      []string
	AllowLocalhost  bool
	ECHMode          string
	RequireSNI       bool
	AllowHTTP        bool
	ProxyEnabled     bool
	ProxyPort        int
	TUNMode          string
	CACertPath       string // Host path to combined CA bundle (in TempDir).
	SystemCACertPath string // System CA file path to bind-mount over.
	CA               *proxy.CA
	EnvSet           map[string]string
	EnvPassthrough   []string
	DegradedLayers   []DegradedLayer
	TempDir          string
	NoFSRestrict     bool
	Quiet            bool
	Command          []string
	Caps             *Capabilities
	Logger           *clog.Logger
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
	DenyWritePaths []string `json:"deny_write_paths,omitempty"`
	DenyExecPaths  []string `json:"deny_exec_paths,omitempty"`
	ExecPaths      []string `json:"exec_paths,omitempty"`
	UsePivotRoot   bool     `json:"use_pivot_root,omitempty"`
	UseLandlock    bool     `json:"use_landlock,omitempty"`
	NoFSRestrict   bool     `json:"no_fs_restrict,omitempty"`
	PidNS          bool     `json:"pid_ns,omitempty"`
	NetEnabled     bool     `json:"net_enabled"`
	ProxyEnabled   bool     `json:"proxy_enabled,omitempty"`
	ProxyPort      int      `json:"proxy_port,omitempty"`
	CACertFile     string   `json:"ca_cert_file,omitempty"`
	CACertMountDst string   `json:"ca_cert_mount_dst,omitempty"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	AllowedIPs     []string `json:"allowed_ips,omitempty"`
	Quiet          bool     `json:"quiet,omitempty"`
	TempDir        string   `json:"temp_dir"`
}

// planRemovals collects exclusion lists during FS and exec resolution,
// passed to resolveDenials to compute sub-path denial overmounts.
type planRemovals struct {
	roRemoves      []string
	rwRemoves      []string
	execRemoves    []string
	noExecRestrict bool
}

// BuildPlan resolves the sandbox enforcement plan from config and capabilities.
// It returns an error only for fatal conditions (user ns unavailable, net required but missing).
func BuildPlan(cfg *config.Config, caps *Capabilities) (*SandboxPlan, error) {
	if runtime.GOOS != "linux" {
		return buildDegradedPlan(cfg, caps)
	}
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

// resolveCapabilities validates system capabilities and selects enforcement layers.
func resolveCapabilities(plan *SandboxPlan, cfg *config.Config, caps *Capabilities) error {
	if caps.UserNS != nil {
		return fmt.Errorf("fatal: %w\n\n%s", caps.UserNS, userNSErrMessage())
	}

	hasFiltering := (len(cfg.AllowedDomains) > 0 || len(cfg.AllowedIPs) > 0) && !cfg.UnrestrictedNet
	if hasFiltering {
		if caps.NetNS != nil {
			return fmt.Errorf("fatal: %w\n\n%s", caps.NetNS, netNSErrMessage())
		}
	}

	// Proxy and netstack mode selection.
	plan.ProxyEnabled = hasFiltering && cfg.ProxyMode != "off"
	needsNetstack := hasFiltering && !plan.ProxyEnabled
	if cfg.TUNMode == "always" && hasFiltering && plan.ProxyEnabled && caps.TUN == nil {
		needsNetstack = true
	}
	if needsNetstack {
		if caps.TUN != nil {
			msg := tunDeviceErrMessage()
			if errors.Is(caps.TUN, errTUNIoctl) {
				msg = tunIoctlErrMessage()
			}
			return fmt.Errorf("fatal: %w\n\n%s", caps.TUN, msg)
		}
	}
	plan.NetEnabled = needsNetstack

	// PID namespace.
	if caps.PidNS == nil {
		plan.PidNS = true
	} else {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "pid namespace",
			Reason: caps.PidNS.Error(),
			Impact: "PID isolation unavailable: the sandboxed process can see host PIDs.",
		})
	}

	// FS/exec enforcement routing: pivot_root (mount NS) is primary for FS,
	// Landlock hardens on top when available.
	if !cfg.NoFSRestrict || !cfg.NoExecRestrict {
		if caps.MountNS == nil && !cfg.NoFSRestrict {
			plan.UsePivotRoot = true
			if caps.LandlockABI > 0 {
				plan.UseLandlock = true
			}
		} else if caps.LandlockABI > 0 {
			plan.UseLandlock = true
		} else {
			return fmt.Errorf("mount namespaces and landlock both unavailable: filesystem and exec restrictions cannot be enforced; use --write '*' --exec '*' to disable them")
		}
	}
	return nil
}

// resolveFilesystem merges default and user-configured paths, expands tildes
// and globs, resolves symlinks, and creates the temp directory.
func resolveFilesystem(plan *SandboxPlan, cfg *config.Config, removals *planRemovals, realHome string) error {
	plan.NoFSRestrict = cfg.NoFSRestrict
	if !cfg.NoFSRestrict {
		// Parse exclusions, expand tildes and globs, then merge with defaults.
		var roAdds []string
		var roRemoveAll bool
		roAdds, removals.roRemoves, roRemoveAll = config.ParseExclusions(cfg.ROPaths)
		if realHome != "" {
			roAdds = config.ExpandTildes(roAdds, realHome)
			removals.roRemoves = config.ExpandTildes(removals.roRemoves, realHome)
		}
		roAdds = config.ExpandGlobs(roAdds)
		removals.roRemoves = config.ExpandGlobs(removals.roRemoves)

		// Apply exclusions to both default RO paths and files.
		roExcl := excludeArgs(removals.roRemoves)
		addDirs, addFiles := splitDirsFiles(roAdds)
		if roRemoveAll {
			plan.ROPaths = addDirs
			plan.ROFiles = addFiles
		} else {
			plan.ROPaths = append(config.ApplyExclusions(config.DefaultROPaths, roExcl), addDirs...)
			plan.ROFiles = append(config.ApplyExclusions(config.DefaultROFiles, roExcl), addFiles...)
		}

		var rwAdds []string
		var rwRemoveAll bool
		rwAdds, removals.rwRemoves, rwRemoveAll = config.ParseExclusions(cfg.RWPaths)
		if realHome != "" {
			rwAdds = config.ExpandTildes(rwAdds, realHome)
			removals.rwRemoves = config.ExpandTildes(removals.rwRemoves, realHome)
		}
		rwAdds = config.ExpandGlobs(rwAdds)
		removals.rwRemoves = config.ExpandGlobs(removals.rwRemoves)
		rwExcl := excludeArgs(removals.rwRemoves)
		rwAddDirs, rwAddFiles := splitDirsFiles(rwAdds)
		if !rwRemoveAll {
			plan.RWPaths = config.ApplyExclusions(config.DefaultRWPaths, rwExcl)
			plan.RWFiles = config.ApplyExclusions(config.DefaultRWFiles, rwExcl)
		}
		plan.RWPaths = append(plan.RWPaths, rwAddDirs...)
		plan.RWFiles = append(plan.RWFiles, rwAddFiles...)

		// CWD: read-only by default (use --write . for write access).
		// Respects --read '!.' and --read '!*'.
		if cwd, err := os.Getwd(); err == nil && !roRemoveAll && !isExcluded(cwd, removals.roRemoves) {
			plan.ROPaths = append(plan.ROPaths, cwd)
		}

		// Resolve symlinks so Landlock covers both the symlink and its
		// target inode. Without this, paths like /etc/resolv.conf ->
		// /run/systemd/resolve/stub-resolv.conf would be inaccessible.
		plan.ROPaths = resolveSymlinks(plan.ROPaths)
		plan.ROFiles = resolveSymlinks(plan.ROFiles)
		plan.RWPaths = resolveSymlinks(plan.RWPaths)
		plan.RWFiles = resolveSymlinks(plan.RWFiles)
	}

	// Temp directory.
	tmpDir, err := os.MkdirTemp("", "curb-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	plan.TempDir = tmpDir
	plan.RWPaths = append(plan.RWPaths, tmpDir)
	return nil
}

// resolveExec resolves exec path allowlists: parse exclusions, look up
// binaries via PATH, resolve symlinks, and ensure exec dirs are readable.
func resolveExec(plan *SandboxPlan, cfg *config.Config, removals *planRemovals, realHome string) error {
	removals.noExecRestrict = cfg.NoExecRestrict
	if cfg.NoExecRestrict {
		return nil
	}
	var execAdds []string
	var execRemoveAll bool
	execAdds, removals.execRemoves, execRemoveAll = config.ParseExclusions(cfg.ExecAllow)
	if realHome != "" {
		execAdds = config.ExpandTildes(execAdds, realHome)
		removals.execRemoves = config.ExpandTildes(removals.execRemoves, realHome)
	}
	removals.execRemoves = config.ExpandGlobs(removals.execRemoves)
	if execRemoveAll {
		plan.ExecPaths = nil
	} else {
		plan.ExecPaths = config.ApplyExclusions(config.SystemExecPaths, excludeArgs(removals.execRemoves))
	}
	for _, name := range execAdds {
		if filepath.IsAbs(name) {
			// Expand globs in absolute exec paths (e.g. /usr/bin/python*).
			plan.ExecPaths = append(plan.ExecPaths, config.ExpandGlobs([]string{name})...)
		} else if abs, lookErr := exec.LookPath(name); lookErr == nil {
			plan.ExecPaths = append(plan.ExecPaths, abs)
		} else {
			return fmt.Errorf("--exec %s: not found in PATH", name)
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
	plan.ExecPaths = resolveSymlinks(plan.ExecPaths)

	// Ensure directories containing exec paths are readable so the
	// child can stat() them for path resolution after Landlock.
	if !cfg.NoFSRestrict {
		plan.ROPaths = appendExecDirs(plan.ROPaths, plan.ExecPaths)
	}
	return nil
}

// resolveNetwork sets domain/IP allowlists, localhost forwarding, and TLS policy.
func resolveNetwork(plan *SandboxPlan, cfg *config.Config) {
	plan.UnrestrictedNet = cfg.UnrestrictedNet
	plan.AllowedDomains = cfg.AllowedDomains
	plan.AllowedIPs = cfg.AllowedIPs
	plan.TUNMode = cfg.TUNMode
	if !cfg.NoFSRestrict && plan.NetEnabled {
		// Ensure /etc/resolv.conf's real path is readable for DNS resolution.
		if dir := resolvConfDir(); dir != "" {
			plan.ROPaths = append(plan.ROPaths, dir)
		}
	}
	// Wildcard or "localhost" in allowed domains implies localhost access.
	plan.AllowLocalhost = slices.Contains(cfg.AllowedDomains, "*") ||
		slices.Contains(cfg.AllowedDomains, "localhost")
	// Loopback IPs in the allowlist also imply localhost forwarding.
	if len(cfg.AllowedIPs) > 0 {
		ipMatcher := policy.NewIPMatcher(cfg.AllowedIPs)
		if ipMatcher.ContainsLoopback() {
			plan.AllowLocalhost = true
		}
	}
	plan.ECHMode = cfg.ECHMode
	plan.RequireSNI = cfg.RequireSNI
	plan.AllowHTTP = cfg.AllowHTTP
}

// resolveProxy picks a proxy port, generates the ephemeral CA, and writes
// the combined CA bundle.
func resolveProxy(plan *SandboxPlan, cfg *config.Config, caps *Capabilities) error {
	if !plan.ProxyEnabled {
		return nil
	}
	plan.ProxyPort = pickProxyPort()
	if plan.NetEnabled {
		// Proxy + TUN: force AllowLocalhost so the proxy is reachable via netstack.
		plan.AllowLocalhost = true
	}
	if cfg.TUNMode == "always" && caps.TUN != nil && !plan.NetEnabled {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "TUN/TAP hardening",
			Reason: caps.TUN.Error(),
			Impact: "TUN unavailable: proxy provides domain filtering but without netstack defense-in-depth.",
		})
	}

	// CA generation.
	ca, caErr := proxy.NewCA()
	if caErr != nil {
		return fmt.Errorf("generating ephemeral CA: %w", caErr)
	}
	plan.CA = ca
	bundlePath, systemPath, caErr := proxy.WriteCombinedBundle(plan.TempDir, ca)
	if caErr != nil {
		return fmt.Errorf("writing CA bundle: %w", caErr)
	}
	plan.CACertPath = bundlePath
	plan.SystemCACertPath = systemPath
	return nil
}

// resolveEnv applies environment policy and sets up shell init files.
func resolveEnv(plan *SandboxPlan, cfg *config.Config) error {
	applyEnvPolicy(plan, cfg, plan.TempDir)
	plan.Command = cfg.Command
	return setupShellInit(plan, plan.TempDir)
}

// resolveDenials collects sub-path denials from exclusions and warns if
// pivot_root is unavailable to enforce them.
func resolveDenials(plan *SandboxPlan, removals *planRemovals) {
	if !plan.NoFSRestrict {
		plan.HiddenPaths = subpathDenials(removals.roRemoves, plan.ROPaths, plan.RWPaths)
		plan.DenyWritePaths = subpathDenials(removals.rwRemoves, plan.ROPaths, plan.RWPaths)
		plan.HiddenPaths = resolveSymlinks(plan.HiddenPaths)
		plan.DenyWritePaths = resolveSymlinks(plan.DenyWritePaths)
	}
	if !removals.noExecRestrict {
		plan.DenyExecPaths = subpathDenials(removals.execRemoves, plan.ExecPaths)
		plan.DenyExecPaths = resolveSymlinks(plan.DenyExecPaths)
	}
	if !plan.UsePivotRoot {
		allDenials := len(plan.HiddenPaths) + len(plan.DenyWritePaths) + len(plan.DenyExecPaths)
		if allDenials > 0 {
			clog.Warnf("sub-path denials (! exclusions) cannot be enforced without mount namespaces: %v", plan.Caps.MountNS)
		}
	}
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
		DenyWritePaths: p.DenyWritePaths,
		DenyExecPaths:  p.DenyExecPaths,
		ExecPaths:      p.ExecPaths,
		UsePivotRoot:   p.UsePivotRoot,
		UseLandlock:    p.UseLandlock,
		NoFSRestrict:   p.NoFSRestrict,
		PidNS:          p.PidNS,
		NetEnabled:     p.NetEnabled,
		ProxyEnabled:   p.ProxyEnabled,
		ProxyPort:      p.ProxyPort,
		CACertFile:     p.CACertPath,
		CACertMountDst: p.SystemCACertPath,
		AllowedDomains: p.AllowedDomains,
		AllowedIPs:     p.AllowedIPs,
		Quiet:          p.Quiet,
		TempDir:        p.TempDir,
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
		for _, e := range os.Environ() {
			k, v, _ := strings.Cut(e, "=")
			if isInternalEnvVar(k) {
				continue
			}
			if _, set := env[k]; set {
				continue
			}
			for _, pat := range p.EnvPassthrough {
				if matched, _ := filepath.Match(pat, k); matched {
					env[k] = v
					break
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
	printCap(w, "PID namespaces", p.Caps.PidNS, "")
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
		pr("    deny read:  %s\n", strings.Join(p.HiddenPaths, " "))
	}
	if len(p.DenyWritePaths) > 0 {
		pr("    deny write: %s\n", strings.Join(p.DenyWritePaths, " "))
	}
	if len(p.DenyExecPaths) > 0 {
		pr("    deny exec:  %s\n", strings.Join(p.DenyExecPaths, " "))
	}
	if len(p.ExecPaths) > 0 {
		pr("    exec:       %s\n", strings.Join(p.ExecPaths, " "))
	}

	// Network.
	ln("  network:")
	if p.UnrestrictedNet {
		ln("    mode:       unrestricted (--unrestricted-net)")
	} else {
		if p.ProxyEnabled {
			pr("    proxy:      on (127.0.0.1:%d)\n", p.ProxyPort)
		} else {
			ln("    proxy:      off")
		}
		tunStatus := "off"
		if p.NetEnabled {
			tunStatus = "on"
		}
		pr("    tun:        %s (%s)\n", p.TUNMode, tunStatus)
		if p.CACertPath != "" {
			pr("    ca cert:    %s\n", p.CACertPath)
		}
		if len(p.AllowedDomains) > 0 {
			pr("    domains:    %s\n", strings.Join(p.AllowedDomains, ", "))
		}
		if len(p.AllowedIPs) > 0 {
			pr("    IPs:        %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if !p.ProxyEnabled && !p.NetEnabled && len(p.AllowedDomains) == 0 && len(p.AllowedIPs) == 0 {
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
		}
		ln("    blocked:    everything else")
	}

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
		var resolved []string
		for _, e := range os.Environ() {
			k, _, _ := strings.Cut(e, "=")
			for _, pat := range p.EnvPassthrough {
				if matched, _ := filepath.Match(pat, k); matched {
					resolved = append(resolved, k)
					break
				}
			}
		}
		sort.Strings(resolved)
		pr("    passthrough: %s\n", strings.Join(resolved, " "))
	}
	ln("    blocked:    everything else")

	// Enforcement method.
	ln("  enforcement:")
	switch {
	case p.UsePivotRoot && p.UseLandlock:
		ln("    method:     pivot_root + landlock")
	case p.UsePivotRoot:
		ln("    method:     pivot_root")
	case p.UseLandlock:
		ln("    method:     landlock")
	default:
		ln("    method:     none (env-only)")
	}
	if len(p.DegradedLayers) > 0 {
		ln("    status:     degraded")
		for _, d := range p.DegradedLayers {
			pr("    warning: %s: %s\n", d.Layer, d.Impact)
		}
	} else {
		ln("    status:     full")
	}
}

func (p *SandboxPlan) capUserInfo() string {
	if p.Caps.KernelInfo != "" {
		return "kernel " + p.Caps.KernelInfo
	}
	return ""
}

// applyEnvPolicy resolves the environment for a sandbox plan from config
// and the temp directory. Used by both BuildPlan and buildDegradedPlan.
func applyEnvPolicy(plan *SandboxPlan, cfg *config.Config, tmpDir string) {
	envAdds, envRemoves, envRemoveAll := config.ParseExclusions(cfg.EnvPassthrough)
	plan.EnvSet = config.DefaultEnvVars(tmpDir, cfg.HomePath)
	if len(cfg.Command) > 0 {
		plan.EnvSet["PS1"] = config.DefaultPS1(cfg.Command[0], os.Getenv("NO_COLOR") != "")
	}
	if envRemoveAll {
		plan.EnvSet = make(map[string]string)
	} else if len(envRemoves) > 0 {
		for _, r := range envRemoves {
			delete(plan.EnvSet, r)
		}
	}
	for _, pair := range cfg.EnvSet {
		k, v, _ := strings.Cut(pair, "=")
		plan.EnvSet[k] = v
	}
	if cfg.EnvPassthroughAll {
		plan.EnvPassthrough = []string{envPassthroughAll}
	} else if envRemoveAll {
		plan.EnvPassthrough = envAdds
	} else {
		plan.EnvPassthrough = config.ApplyExclusions(config.SafePassthroughVars, excludeArgs(envRemoves))
		plan.EnvPassthrough = append(plan.EnvPassthrough, envAdds...)
	}

	// Proxy env vars.
	if plan.ProxyEnabled {
		proxyURL := fmt.Sprintf("http://127.0.0.1:%d", plan.ProxyPort)
		plan.EnvSet["HTTPS_PROXY"] = proxyURL
		plan.EnvSet["HTTP_PROXY"] = proxyURL
		plan.EnvSet["https_proxy"] = proxyURL
		plan.EnvSet["http_proxy"] = proxyURL
		if plan.CACertPath != "" {
			plan.EnvSet["SSL_CERT_FILE"] = plan.CACertPath
			plan.EnvSet["CURL_CA_BUNDLE"] = plan.CACertPath
			plan.EnvSet["REQUESTS_CA_BUNDLE"] = plan.CACertPath
			plan.EnvSet["NODE_EXTRA_CA_CERTS"] = plan.CACertPath
			plan.EnvSet["SSL_CERT_DIR"] = "" // Clear to prevent stale dir overriding the bundle file.
		}
	}
}

// setupShellInit writes shell init files into tmpDir so the (curb) PS1 prefix
// survives rc file processing. For bash, a custom --rcfile is injected. For
// zsh, ZDOTDIR is redirected to tmpDir with forwarding init files.
func setupShellInit(plan *SandboxPlan, tmpDir string) error {
	if len(plan.Command) == 0 {
		return nil
	}
	shell := filepath.Base(plan.Command[0])
	noColor := os.Getenv("NO_COLOR") != ""

	// Resolve the user's original home directory for sourcing rc files.
	// Inside the sandbox HOME is typically tmpDir, so using $HOME would
	// cause the init files to source themselves (infinite recursion).
	origHome := os.Getenv("ZDOTDIR")
	if origHome == "" {
		origHome = os.Getenv("HOME")
	}

	switch shell {
	case "bash":
		// Skip if non-interactive or user already controls rc file loading.
		for _, a := range plan.Command[1:] {
			if a == "-c" || a == "--rcfile" || a == "--init-file" || a == "--norc" {
				return nil
			}
		}
		rcFile := filepath.Join(tmpDir, ".curb.bashrc")
		var ps1Expr string
		if noColor {
			ps1Expr = `(curb) $PS1`
		} else {
			ps1Expr = `\[\033[36m\](curb)\[\033[0m\] $PS1`
		}
		var content string
		if origHome != "" {
			// Source user's bashrc if accessible (may be blocked by sandbox).
			content = ". " + origHome + "/.bashrc 2>/dev/null\n"
		}
		content += "PS1=\"" + ps1Expr + "\"\n"
		if err := os.WriteFile(rcFile, []byte(content), 0o644); err != nil {
			return err
		}
		plan.Command = slices.Insert(plan.Command, 1, "--rcfile", rcFile)
		delete(plan.EnvSet, "PS1")

	case "zsh":
		// Redirect ZDOTDIR to tmpDir with forwarding init files.
		plan.EnvSet["ZDOTDIR"] = tmpDir

		// Forward .zshenv so the user's environment setup is preserved.
		var zshenv string
		if origHome != "" {
			zshenv = ". " + origHome + "/.zshenv 2>/dev/null\n"
		}
		_ = os.WriteFile(filepath.Join(tmpDir, ".zshenv"), []byte(zshenv), 0o644)

		// Forward .zshrc, then set PS1.
		var ps1Expr string
		if noColor {
			ps1Expr = `(curb) $PS1`
		} else {
			ps1Expr = `%F{cyan}(curb)%f $PS1`
		}
		var zshrc string
		if origHome != "" {
			zshrc = ". " + origHome + "/.zshrc 2>/dev/null\n"
		}
		zshrc += "PS1=\"" + ps1Expr + "\"\n"
		if err := os.WriteFile(filepath.Join(tmpDir, ".zshrc"), []byte(zshrc), 0o644); err != nil {
			return err
		}
		delete(plan.EnvSet, "PS1")
	}
	return nil
}

// splitDirsFiles classifies paths into directories and regular files by stat.
// Paths that don't exist or can't be stat'd are assumed to be directories.
func splitDirsFiles(paths []string) (dirs, files []string) {
	for _, p := range paths {
		info, err := os.Stat(p)
		if err == nil && !info.IsDir() {
			files = append(files, p)
		} else {
			dirs = append(dirs, p)
		}
	}
	return
}

// subpathDenials returns exclusions that are sub-paths of any allowed parent
// directory. These are paths that need active denial (overmount) because
// pivot_root's default-deny doesn't cover them.
func subpathDenials(removes []string, dirSets ...[]string) []string {
	var denials []string
	for _, r := range removes {
		abs, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		for _, dirs := range dirSets {
			found := false
			for _, dir := range dirs {
				if isSubpath(abs, dir) {
					denials = append(denials, abs)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
	}
	return denials
}

// isSubpath reports whether child is strictly under parent.
func isSubpath(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != "." && !strings.HasPrefix(rel, "..")
}

// isExcluded checks whether path matches any of the exclusion entries,
// resolving relative entries to absolute paths for comparison.
func isExcluded(path string, excludes []string) bool {
	for _, e := range excludes {
		abs, err := filepath.Abs(e)
		if err != nil {
			continue
		}
		if abs == path {
			return true
		}
	}
	return false
}

// excludeArgs converts plain strings into "!"-prefixed exclusion args for ApplyExclusions.
func excludeArgs(items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = "!" + s
	}
	return out
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
			if dir == ro || isSubpath(dir, ro) {
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

// resolveSymlinks evaluates symlinks in paths and appends any resolved paths
// that differ from the original, so Landlock covers both the symlink and its
// target. Errors are silently ignored (the path may not exist yet).
func resolveSymlinks(paths []string) []string {
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

	if len(cfg.AllowedDomains) > 0 {
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
	applyEnvPolicy(plan, cfg, tmpDir)
	// Remove IS_SANDBOX: no user namespace isolation on this platform.
	delete(plan.EnvSet, "IS_SANDBOX")

	plan.Command = cfg.Command
	return plan, nil
}

// pickProxyPort picks a random port for the proxy listener inside the sandbox.
// The port is in the ephemeral range (49152-65535).
func pickProxyPort() int {
	// Use a random port. In the isolated net NS, collisions are impossible
	// (nothing else is listening). The port is fixed at plan time so it can
	// be passed to the child via ChildConfig.
	return 49152 + rand.IntN(16384)
}

// listenProxyPort creates a TCP listener on the proxy port.
// Used by the parent in proxy+TUN mode.
func listenProxyPort(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
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
