package sandbox

import (
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"os"
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

	// TestNoMountNSEnvKey disables mount NS in tests to exercise Landlock-only path.
	TestNoMountNSEnvKey = "_CURB_TEST_NO_MOUNT_NS"

	// TestNoUserNSEnvKey disables user NS in tests to exercise the Landlock-only direct-exec path.
	TestNoUserNSEnvKey = "_CURB_TEST_NO_USER_NS"

	// TestNoSeccompEnvKey disables seccomp in tests to exercise paths without AF_UNIX blocking.
	TestNoSeccompEnvKey = "_CURB_TEST_NO_SECCOMP"

	// SOCKSAddrEnvKey is the env var holding the SOCKS5 proxy address for the
	// _socks-connect helper (used as SSH ProxyCommand).
	SOCKSAddrEnvKey = "_CURB_SOCKS_ADDR"

	// defaultNoProxy is the NO_PROXY value for sandbox-internal localhost.
	defaultNoProxy = "localhost,127.0.0.1,::1"
)

// FSEnforcer applies a filesystem enforcement layer to the current process.
// Implementations capture their configuration at construction time.
// Linux: pivotRootEnforcer (mountfs_linux.go), landlockEnforcer (child_linux.go).
type FSEnforcer interface {
	Enforce() error
}

// DegradedLayer records a sandbox layer that cannot be fully enforced.
type DegradedLayer struct {
	Layer  string
	Reason string
	Impact string
}

// SandboxPlan is the resolved enforcement plan derived from Config + Capabilities.
type SandboxPlan struct {
	ROPaths          []string
	ROFiles          []string
	RWPaths          []string
	RWFiles          []string
	HiddenPaths      []string
	DenyWritePaths   []string
	DenyExecPaths    []string
	ExecPaths        []string
	UsePivotRoot     bool
	UseLandlock      bool
	UseSeatbelt      bool
	PidNS            bool
	NoUserNS         bool
	UnrestrictedNet  bool
	AllowedDomains   []string
	AllowedIPs       []string
	HostLoopback     bool
	AllowUnixSockets bool
	ProxyEnabled     bool
	ProxyPort        int
	SOCKSPort        int
	SSHConfigPath    string      // Host path to generated SSH config (in TempDir).
	SSHConfigDst     string      // Target path to bind-mount over (~/.ssh/config).
	SkillMounts      [][2]string // [src, dst] pairs for skill directory bind-mounts.
	UserPaths        []string    // Paths explicitly requested by the user (--read/--write/--exec adds).
	EnvSet           map[string]string
	EnvPassthrough   []string
	DegradedLayers   []DegradedLayer
	TempDir          string
	SandboxHome      string // Resolved HOME for the sandbox (used for tilde expansion and env fallback).
	NoFSRestrict     bool
	NoExecRestrict   bool
	Quiet            bool
	Command          []string
	Caps             *Capabilities
	Logger           *clog.Logger

	// Credential injection (parent-only; never serialized to the child).
	// CA mints leaf certs for injected hosts; InjectBindings maps a host to
	// the credential headers the proxy attaches to it.
	CA             *proxy.CA
	InjectBindings map[string][]proxy.Injection
}

// LandlockPaths returns the path sets for Landlock rule construction.
func (p *SandboxPlan) LandlockPaths() policy.LandlockPaths {
	return policy.LandlockPaths{
		RODirs:  p.ROPaths,
		ROFiles: p.ROFiles,
		RWDirs:  p.RWPaths,
		RWFiles: p.RWFiles,
		Exec:    p.ExecPaths,
	}
}

// ChildConfig is the serializable config sent from parent to child over a pipe.
type ChildConfig struct {
	Command           []string    `json:"command"`
	Env               []string    `json:"env"`
	ROPaths           []string    `json:"ro_paths,omitempty"`
	ROFiles           []string    `json:"ro_files,omitempty"`
	RWPaths           []string    `json:"rw_paths,omitempty"`
	RWFiles           []string    `json:"rw_files,omitempty"`
	HiddenPaths       []string    `json:"hidden_paths,omitempty"`
	DenyWritePaths    []string    `json:"deny_write_paths,omitempty"`
	DenyExecPaths     []string    `json:"deny_exec_paths,omitempty"`
	ExecPaths         []string    `json:"exec_paths,omitempty"`
	UsePivotRoot      bool        `json:"use_pivot_root,omitempty"`
	UseLandlock       bool        `json:"use_landlock,omitempty"`
	NoFSRestrict      bool        `json:"no_fs_restrict,omitempty"`
	PidNS             bool        `json:"pid_ns,omitempty"`
	ProxyEnabled      bool        `json:"proxy_enabled,omitempty"`
	ProxyPort         int         `json:"proxy_port,omitempty"`
	SOCKSPort         int         `json:"socks_port,omitempty"`
	SSHConfigFile     string      `json:"ssh_config_file,omitempty"`
	SSHConfigMountDst string      `json:"ssh_config_mount_dst,omitempty"`
	SkillMounts       [][2]string `json:"skill_mounts,omitempty"`
	AllowedDomains    []string    `json:"allowed_domains,omitempty"`
	AllowedIPs        []string    `json:"allowed_ips,omitempty"`
	UserPaths         []string    `json:"user_paths,omitempty"`
	AllowUnixSockets  bool        `json:"allow_unix_sockets,omitempty"`
	Quiet             bool        `json:"quiet,omitempty"`
	Verbose           bool        `json:"verbose,omitempty"`
	Debug             bool        `json:"debug,omitempty"`
	TempDir           string      `json:"temp_dir"`
}

// LandlockPaths returns the path sets for Landlock rule construction.
func (c *ChildConfig) LandlockPaths() policy.LandlockPaths {
	return policy.LandlockPaths{
		RODirs:  c.ROPaths,
		ROFiles: c.ROFiles,
		RWDirs:  c.RWPaths,
		RWFiles: c.RWFiles,
		Exec:    c.ExecPaths,
	}
}

// planRemovals collects exclusion lists during FS and exec resolution,
// passed to resolveDenials to compute sub-path denial overmounts.
type planRemovals struct {
	roRemoves      []string
	rwRemoves      []string
	execRemoves    []string
	noExecRestrict bool
}

// PlanBuilder creates a SandboxPlan from configuration and probed capabilities.
// Each platform provides an implementation via newPlanBuilder() (build-tagged).
type PlanBuilder interface {
	BuildPlan(cfg *config.Config, caps *Capabilities, logger *clog.Logger) (*SandboxPlan, error)
}

// BuildPlan resolves the sandbox enforcement plan from config and capabilities.
// It delegates to the platform-specific PlanBuilder returned by newPlanBuilder().
func BuildPlan(cfg *config.Config, caps *Capabilities, logger *clog.Logger) (*SandboxPlan, error) {
	return newPlanBuilder().BuildPlan(cfg, caps, logger)
}

// resolveCapabilities validates system capabilities and selects enforcement layers.
func resolveCapabilities(plan *SandboxPlan, cfg *config.Config, caps *Capabilities) error {
	hasFiltering := (len(cfg.AllowedDomains) > 0 || len(cfg.AllowedIPs) > 0 || cfg.HostLoopback) && !cfg.UnrestrictedNet

	if caps.UserNS != nil {
		aaHint := ""
		if caps.AppArmorRestricted {
			aaHint = "\n" + apparmorSetupHint
		}
		if caps.LandlockABI == 0 {
			return fmt.Errorf("fatal: user namespaces and Landlock both unavailable: %w\n\n%s%s", caps.UserNS, userNSErrMessage(), aaHint)
		}
		if hasFiltering {
			return fmt.Errorf("--domains/--ips require user namespaces: %w%s", caps.UserNS, aaHint)
		}
		if !cfg.UnrestrictedNet {
			return fmt.Errorf("user namespaces unavailable: network cannot be restricted; use --unrestricted-net to allow unrestricted network: %w%s", caps.UserNS, aaHint)
		}
		// Landlock-only mode: no namespaces, no network filtering.
		// UnrestrictedNet is set by resolveNetwork from cfg.UnrestrictedNet.
		plan.NoUserNS = true
		plan.UseLandlock = true
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "user namespace",
			Reason: caps.UserNS.Error(),
			Impact: "No mount/network/PID namespaces: FS enforcement via Landlock only, network unrestricted.",
		})
		// Skip net/mount/PID capability checks (all require user NS).
		return nil
	}
	if hasFiltering {
		if caps.NetNS != nil {
			return fmt.Errorf("fatal: %w\n\n%s", caps.NetNS, netNSErrMessage())
		}
	}

	plan.ProxyEnabled = hasFiltering

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

// createTempDir creates a temporary directory for the sandbox.
func createTempDir() (string, error) {
	return os.MkdirTemp("", "curb-")
}

// resolveHostHome returns the host user's home directory, or "" if it
// cannot be determined. Used as the resolution target for ~ in path fields.
func resolveHostHome() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// stripExclusionPrefix removes a leading "!" or "\!" exclusion marker from
// a configured path entry, returning the bare path.
func stripExclusionPrefix(p string) string {
	switch {
	case strings.HasPrefix(p, `\!`):
		return p[2:]
	case strings.HasPrefix(p, "!"):
		return p[1:]
	}
	return p
}

// anyPathReferencesHome reports whether any entry across the three path
// lists is a host-home reference (~ or an internal $HOME marker).
func anyPathReferencesHome(cfg *config.Config) bool {
	for _, paths := range [][]string{cfg.ROPaths, cfg.RWPaths, cfg.ExecAllow} {
		for _, p := range paths {
			if config.PathReferencesHome(stripExclusionPrefix(p)) {
				return true
			}
		}
	}
	return false
}

// checkHostHomeResolvable returns an error if any configured path uses ~
// or $HOME but the host home could not be determined. Without this check,
// expansion silently produces broken paths like "/.ssh" from "~/.ssh".
func checkHostHomeResolvable(cfg *config.Config, hostHome string) error {
	if hostHome != "" || !anyPathReferencesHome(cfg) {
		return nil
	}
	return fmt.Errorf("cannot resolve ~ or $HOME in paths: host home directory is unavailable (set $HOME, or remove ~ / $HOME references from profiles and config)")
}

// warnHostHomePathMismatch logs a warning when a configured path references
// the host home (via literal ~ or $HOME) and the sandbox's $HOME will
// differ — in that case the granted paths cannot be reached by the
// sandboxed program via its own $HOME. Already-literal host-home paths
// (e.g. a user-written "/home/user/.ssh") are excluded — those are the
// user's explicit choice, not a variable-expansion surprise.
func warnHostHomePathMismatch(cfg *config.Config, sandboxHome, hostHome string) {
	if hostHome == "" || sandboxHome == hostHome {
		return
	}
	if !anyPathReferencesHome(cfg) {
		return
	}
	clog.Warnf("~ or $HOME in paths resolves to the host home (%s), but the sandbox's $HOME will be %s — the sandboxed program cannot reach these paths via its own $HOME. Use --env HOME to align them, or ignore this warning if you meant the host path.", hostHome, sandboxHome)
}

// resolveSandboxHome determines what HOME will be inside the sandbox.
// Priority: explicit --env HOME=/path > --env HOME passthrough > tmpDir fallback.
func resolveSandboxHome(cfg *config.Config, tmpDir string) string {
	// Check explicit set: --env HOME=/path.
	for _, pair := range cfg.EnvSet {
		if k, v, ok := strings.Cut(pair, "="); ok && k == "HOME" {
			return v
		}
	}
	// Check passthrough-all: --env '*'.
	if cfg.EnvPassthroughAll {
		if h, ok := os.LookupEnv("HOME"); ok {
			return h
		}
	}
	// Check explicit passthrough: --env HOME.
	// Always check adds even after !* — "!*" clears defaults but
	// subsequent adds still apply (e.g. --env '!*' --env HOME).
	adds, _, _ := config.ParseExclusions(cfg.EnvPassthrough)
	for _, name := range adds {
		if name == "HOME" {
			if h, ok := os.LookupEnv("HOME"); ok {
				return h
			}
		}
	}
	return tmpDir
}

// resolveFilesystem merges default and user-configured paths, expands tildes
// and globs, resolves symlinks. The temp directory must already be set on
// plan.TempDir. The hostHome parameter is the target for ~ expansion.
func resolveFilesystem(plan *SandboxPlan, cfg *config.Config, removals *planRemovals, hostHome string) error {
	plan.NoFSRestrict = cfg.NoFSRestrict
	if !cfg.NoFSRestrict {
		// Parse exclusions, expand tildes and globs, then merge with defaults.
		var roAdds []string
		var roRemoveAll bool
		roAdds, removals.roRemoves, roRemoveAll = config.ParseExclusions(cfg.ROPaths)
		roAdds = config.ExpandHomeRefs(roAdds, hostHome)
		removals.roRemoves = config.ExpandHomeRefs(removals.roRemoves, hostHome)
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
		rwAdds = config.ExpandHomeRefs(rwAdds, hostHome)
		removals.rwRemoves = config.ExpandHomeRefs(removals.rwRemoves, hostHome)
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

		// Track user-specified paths for better warnings on bind mount failures.
		plan.UserPaths = append(plan.UserPaths, addDirs...)
		plan.UserPaths = append(plan.UserPaths, addFiles...)
		plan.UserPaths = append(plan.UserPaths, rwAddDirs...)
		plan.UserPaths = append(plan.UserPaths, rwAddFiles...)

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

	// TempDir is always writable.
	plan.RWPaths = append(plan.RWPaths, plan.TempDir)
	return nil
}

// resolveExec resolves exec path allowlists: parse exclusions, look up
// binaries via PATH, resolve symlinks, and ensure exec dirs are readable.
// Binaries not found in PATH are silently skipped (logged at debug level).
func resolveExec(plan *SandboxPlan, cfg *config.Config, removals *planRemovals, hostHome string, logger *clog.Logger) error {
	removals.noExecRestrict = cfg.NoExecRestrict
	if cfg.NoExecRestrict {
		plan.NoExecRestrict = true
		// Ensure the command binary's directory is mounted even though
		// exec resolution is skipped. Use ROPaths (not ExecPaths) so
		// Landlock does not restrict EXECUTE.
		if len(cfg.Command) > 0 {
			cmd0 := cfg.Command[0]
			var resolved string
			if filepath.IsAbs(cmd0) {
				resolved = cmd0
			} else if abs, lookErr := exec.LookPath(cmd0); lookErr == nil {
				resolved = abs
			}
			if resolved != "" {
				for _, p := range resolveSymlinks([]string{resolved}) {
					if dir := filepath.Dir(p); dir != "" && dir != "." {
						plan.ROPaths = appendUniq(plan.ROPaths, dir)
					}
				}
			}
		}
		return nil
	}
	var execAdds []string
	var execRemoveAll bool
	execAdds, removals.execRemoves, execRemoveAll = config.ParseExclusions(cfg.ExecAllow)
	execAdds = config.ExpandHomeRefs(execAdds, hostHome)
	removals.execRemoves = config.ExpandHomeRefs(removals.execRemoves, hostHome)
	removals.execRemoves = config.ExpandGlobs(removals.execRemoves)
	if execRemoveAll {
		plan.ExecPaths = nil
	} else {
		plan.ExecPaths = config.ApplyExclusions(config.SystemExecPaths, excludeArgs(removals.execRemoves))
	}
	// Always include dynamic linker directories so dynamically-linked
	// binaries work even with --exec '!*'. The kernel checks Landlock
	// EXECUTE when loading the ELF interpreter via open_exec().
	// Added after exclusion processing intentionally: --exec '!/lib'
	// cannot remove them, since doing so would break all dynamic linking.
	plan.ExecPaths = append(plan.ExecPaths, linkerExecPaths()...)
	for _, name := range execAdds {
		if strings.ContainsRune(name, filepath.Separator) {
			// Path (absolute or relative): expand globs, resolve to absolute.
			resolved := config.ExpandGlobs([]string{name})
			if len(resolved) == 0 {
				return fmt.Errorf("--exec %s: no matches found", name)
			}
			for i, r := range resolved {
				if !filepath.IsAbs(r) {
					abs, err := filepath.Abs(r)
					if err != nil {
						return fmt.Errorf("--exec %s: %w", r, err)
					}
					resolved[i] = abs
				}
			}
			plan.ExecPaths = append(plan.ExecPaths, resolved...)
			plan.UserPaths = append(plan.UserPaths, resolved...)
		} else if abs, lookErr := exec.LookPath(name); lookErr == nil {
			logger.Debug("exec: %s -> %s", name, abs)
			plan.ExecPaths = append(plan.ExecPaths, abs)
			plan.UserPaths = append(plan.UserPaths, abs)
		} else {
			logger.Debug("exec: %s not found in PATH, skipping", name)
		}
	}

	// Ensure the command binary itself is in ExecPaths so it can be
	// executed (and its directory is mounted in the mount namespace).
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

	// Allow exec from the sandbox temp dir so build tools (go test, cargo
	// test, etc.) can compile and run binaries from the build cache.
	// Skip when the user explicitly cleared all exec paths (--exec '!*').
	if plan.TempDir != "" && !execRemoveAll {
		plan.ExecPaths = append(plan.ExecPaths, plan.TempDir)
	}

	// Ensure directories containing exec paths are readable so the
	// child can stat() them for path resolution after Landlock.
	if !cfg.NoFSRestrict {
		plan.ROPaths = appendExecDirs(plan.ROPaths, plan.ExecPaths, plan.TempDir)
	}
	return nil
}

// linkerExecPaths returns directories needed for the dynamic linker. On Linux,
// the kernel checks Landlock EXECUTE when loading the ELF interpreter via
// open_exec(). On other platforms, the dynamic linker is handled by the OS
// (macOS system.sb handles dyld).
func linkerExecPaths() []string {
	if runtime.GOOS == "linux" {
		return []string{"/lib", "/lib64"}
	}
	return nil
}

// resolveNetwork sets domain/IP allowlists, localhost forwarding, and TLS policy.
func resolveNetwork(plan *SandboxPlan, cfg *config.Config) {
	plan.UnrestrictedNet = cfg.UnrestrictedNet
	plan.AllowedDomains = cfg.AllowedDomains
	plan.AllowedIPs = cfg.AllowedIPs
	plan.HostLoopback = cfg.HostLoopback
	plan.AllowUnixSockets = cfg.AllowUnixSockets
}

// resolveProxy picks proxy ports and ensures the curb binary is accessible
// for the SOCKS5 ProxyCommand helper.
func resolveProxy(plan *SandboxPlan) error {
	if !plan.ProxyEnabled {
		return nil
	}
	plan.ProxyPort = pickProxyPort()
	// Adjacent port in the isolated net NS — no collision possible.
	plan.SOCKSPort = plan.ProxyPort + 1

	// Ensure curb's own binary is accessible inside the sandbox for the
	// _socks-connect ProxyCommand helper.
	if plan.SOCKSPort > 0 {
		if self, err := os.Executable(); err == nil {
			if dir := filepath.Dir(self); dir != "" && dir != "." {
				plan.ROPaths = appendUniq(plan.ROPaths, dir)
				if plan.NoExecRestrict {
					// With --exec '*', keep ExecPaths empty so Landlock
					// does not restrict EXECUTE. The binary is already
					// accessible via its parent directory in ROPaths.
					plan.ROFiles = appendUniq(plan.ROFiles, self)
				} else {
					plan.ExecPaths = appendUniq(plan.ExecPaths, self)
				}
			}
		}
	}
	return nil
}

func appendUniq(s []string, v string) []string {
	if !slices.Contains(s, v) {
		return append(s, v)
	}
	return s
}

// injectSpec is a parsed injection binding: for requests to host, set header to
// prefix + the resolved token. The token comes from source (an @ENV_VAR
// reference or a literal). --inject-bearer fills prefix with "Bearer ".
type injectSpec struct {
	host   string
	header string
	prefix string
	source string
}

// parseInjectBearer parses --inject-bearer "HOST=SOURCE" into an Authorization:
// Bearer binding (sugar over parseInjectHeader).
func parseInjectBearer(entries []string) ([]injectSpec, error) {
	var specs []injectSpec
	for _, e := range entries {
		host, source, ok := strings.Cut(e, "=")
		if !ok || host == "" || source == "" {
			return nil, fmt.Errorf("--inject-bearer must be HOST=SOURCE, got %q", e)
		}
		host, err := normalizeInjectHost(host)
		if err != nil {
			return nil, fmt.Errorf("--inject-bearer host: %w", err)
		}
		specs = append(specs, injectSpec{host: host, header: "Authorization", prefix: "Bearer ", source: source})
	}
	return specs, nil
}

// normalizeInjectHost validates a credential-injection host and returns it
// normalized (lowercase, no trailing dot). Unlike --domains, an injection host
// must be an exact hostname: a wildcard would broaden the allowlist (in the
// case of "*", to every domain) while never matching a binding at runtime, so
// the credential would never be injected.
func normalizeInjectHost(host string) (string, error) {
	if err := policy.ValidateDomains([]string{host}); err != nil {
		return "", err
	}
	if strings.Contains(host, "*") {
		return "", fmt.Errorf("%q must be an exact hostname (no wildcards)", host)
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "."), nil
}

// parseInjectHeader parses --inject-header "HOST=HEADER=SOURCE" into a binding
// that sets an arbitrary request header (e.g. x-api-key) to the resolved token.
func parseInjectHeader(entries []string) ([]injectSpec, error) {
	var specs []injectSpec
	for _, e := range entries {
		parts := strings.SplitN(e, "=", 3)
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, fmt.Errorf("--inject-header must be HOST=HEADER=SOURCE, got %q", e)
		}
		host, header, source := parts[0], parts[1], parts[2]
		host, err := normalizeInjectHost(host)
		if err != nil {
			return nil, fmt.Errorf("--inject-header host: %w", err)
		}
		if strings.ContainsAny(header, " \t:") {
			return nil, fmt.Errorf("--inject-header header name %q is not a valid token", header)
		}
		specs = append(specs, injectSpec{host: host, header: header, source: source})
	}
	return specs, nil
}

// resolveInject generates the per-run CA, resolves each bound token, and
// delivers the CA to the sandbox trust store. It runs after proxy and env
// resolution. The CA key and tokens stay in the parent; only the public CA
// (in a combined bundle) and the placeholder-free env reach the child.
func resolveInject(plan *SandboxPlan, specs []injectSpec) error {
	if len(specs) == 0 {
		return nil
	}
	bindings := make(map[string][]proxy.Injection, len(specs))
	for _, s := range specs {
		token, ok, err := resolveSecretSource(s.source, plan.Logger)
		if err != nil {
			return err
		}
		if !ok {
			continue // optional source (@?VAR) absent — skip this binding
		}
		bindings[s.host] = append(bindings[s.host], proxy.Injection{Header: s.header, Value: s.prefix + token})
	}
	if len(bindings) == 0 {
		return nil // nothing to inject (all sources were optional and absent)
	}
	if !plan.ProxyEnabled {
		return fmt.Errorf("credential injection requires the network proxy (needs user and network namespaces)")
	}
	ca, err := proxy.NewCA()
	if err != nil {
		return fmt.Errorf("generating per-run CA: %w", err)
	}
	plan.CA = ca
	plan.InjectBindings = bindings

	// Trust-store delivery: a combined bundle (system roots + per-run CA) the
	// action trusts for the proxy's leaf certs. The CA validates only inside
	// this run, so it is not sensitive to the action.
	bundle, err := writeCABundle(plan.TempDir, ca.CertPEM())
	if err != nil {
		return err
	}
	plan.ROFiles = appendUniq(plan.ROFiles, bundle)
	for _, k := range []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"} {
		plan.EnvSet[k] = bundle
	}
	return nil
}

// resolveSecretSource reads a token from a credential-injection source. It
// returns ok=false (no error) when an optional @?ENV_VAR source is unset, so
// the caller can skip that binding.
//
//   - @?VAR — optional: the var's value if set and non-empty, else skip.
//   - @VAR  — required: the var's value, or an error if unset or empty.
//   - literal — returned as-is (warning that argv is world-readable).
func resolveSecretSource(source string, log *clog.Logger) (string, bool, error) {
	if name, ok := strings.CutPrefix(source, "@?"); ok {
		val, present := os.LookupEnv(name)
		if !present || val == "" {
			return "", false, nil
		}
		return val, true, nil
	}
	if name, ok := strings.CutPrefix(source, "@"); ok {
		val, present := os.LookupEnv(name)
		if !present || val == "" {
			return "", false, fmt.Errorf("credential injection source $%s is unset or empty", name)
		}
		return val, true, nil
	}
	log.Warn("credential injection literal token is visible in process arguments; prefer @ENV_VAR")
	return source, true, nil
}

// writeCABundle writes a PEM bundle of the system roots plus the per-run CA to
// the temp dir and returns its path.
func writeCABundle(tmpDir string, caPEM []byte) (string, error) {
	var buf []byte
	if sys := systemCABundle(); sys != "" {
		if data, err := os.ReadFile(sys); err == nil {
			buf = append(buf, data...)
			if len(buf) > 0 && buf[len(buf)-1] != '\n' {
				buf = append(buf, '\n')
			}
		}
	}
	buf = append(buf, caPEM...)
	path := filepath.Join(tmpDir, "ca-bundle.pem")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		return "", fmt.Errorf("writing CA bundle: %w", err)
	}
	return path, nil
}

// systemCABundle returns the first system CA bundle found, or "".
func systemCABundle() string {
	for _, p := range []string{
		"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Alpine
		"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora, RHEL
		"/etc/ssl/ca-bundle.pem",                            // openSUSE
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
		"/etc/ssl/cert.pem",                                 // macOS, some BSDs
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// resolveEnv applies environment policy, sets up shell init files, and writes
// an SSH config for ProxyCommand routing through the SOCKS5 proxy.
func resolveEnv(plan *SandboxPlan, cfg *config.Config) error {
	applyEnvPolicy(plan, cfg, plan.TempDir)
	plan.Command = cfg.Command
	if err := setupSSHConfig(plan, plan.TempDir); err != nil {
		return err
	}
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
	if !plan.UsePivotRoot && !plan.UseSeatbelt {
		allDenials := len(plan.HiddenPaths) + len(plan.DenyWritePaths) + len(plan.DenyExecPaths)
		if allDenials > 0 {
			clog.Warnf("sub-path denials (! exclusions) cannot be enforced without mount namespaces: %v", plan.Caps.MountNS)
		}
	}
}

// childConfig builds the ChildConfig from the plan, resolving the environment.
func (p *SandboxPlan) childConfig() ChildConfig {
	return ChildConfig{
		Command:           p.Command,
		Env:               p.ResolveEnv(),
		ROPaths:           p.ROPaths,
		ROFiles:           p.ROFiles,
		RWPaths:           p.RWPaths,
		RWFiles:           p.RWFiles,
		HiddenPaths:       p.HiddenPaths,
		DenyWritePaths:    p.DenyWritePaths,
		DenyExecPaths:     p.DenyExecPaths,
		ExecPaths:         p.ExecPaths,
		UsePivotRoot:      p.UsePivotRoot,
		UseLandlock:       p.UseLandlock,
		NoFSRestrict:      p.NoFSRestrict,
		PidNS:             p.PidNS,
		ProxyEnabled:      p.ProxyEnabled,
		ProxyPort:         p.ProxyPort,
		SOCKSPort:         p.SOCKSPort,
		SSHConfigFile:     p.SSHConfigPath,
		SSHConfigMountDst: p.SSHConfigDst,
		SkillMounts:       p.SkillMounts,
		AllowedDomains:    p.AllowedDomains,
		AllowedIPs:        p.AllowedIPs,
		AllowUnixSockets:  p.AllowUnixSockets,
		UserPaths:         p.UserPaths,
		Quiet:             p.Quiet,
		Verbose:           p.Logger.IsVerbose(),
		Debug:             p.Logger.IsDebug(),
		TempDir:           p.TempDir,
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
	// HOME fallback: use the pre-resolved SandboxHome so tilde expansion
	// and the runtime HOME always agree.
	if _, ok := env["HOME"]; !ok && p.SandboxHome != "" {
		env["HOME"] = p.SandboxHome
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
	if p.UseSeatbelt {
		printCap(w, "seatbelt", p.Caps.Seatbelt, "sandbox-exec")
		if p.Caps.OSVersion != "" {
			printCap(w, "macOS version", nil, p.Caps.OSVersion)
		}
	} else {
		printCap(w, "user namespaces", p.Caps.UserNS, p.capUserInfo())
		printCap(w, "mount namespaces", p.Caps.MountNS, "")
		printCap(w, "PID namespaces", p.Caps.PidNS, "")
		printCap(w, "network namespaces", p.Caps.NetNS, "")
		if p.Caps.LandlockABI > 0 {
			printCap(w, "landlock", nil, fmt.Sprintf("ABI v%d", p.Caps.LandlockABI))
		} else {
			printCap(w, "landlock", fmt.Errorf("unavailable"), "")
		}
		if p.Caps.Seccomp {
			printCap(w, "seccomp", nil, "AF_UNIX blocked")
		} else {
			printCap(w, "seccomp", fmt.Errorf("disabled"), "")
		}
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
			pr("    proxy:      127.0.0.1:%d", p.ProxyPort)
			if p.SOCKSPort > 0 {
				pr(" (socks5 127.0.0.1:%d)", p.SOCKSPort)
			}
			pr("\n")
		}
		if len(p.AllowedDomains) > 0 {
			pr("    domains:    %s\n", strings.Join(p.AllowedDomains, ", "))
		}
		if len(p.AllowedIPs) > 0 {
			pr("    IPs:        %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if !p.ProxyEnabled && len(p.AllowedDomains) == 0 && len(p.AllowedIPs) == 0 {
			ln("    allowed:    none (no network interface)")
		}
		if p.HostLoopback {
			ln("    localhost:  forwarded to host (--host-loopback)")
		} else if p.ProxyEnabled {
			ln("    localhost:  sandbox-internal (NO_PROXY)")
		}
		ln("    blocked:    everything else")
		if len(p.InjectBindings) > 0 {
			hosts := make([]string, 0, len(p.InjectBindings))
			for h := range p.InjectBindings {
				hosts = append(hosts, h)
			}
			sort.Strings(hosts)
			ln("    inject:     TLS terminated; credential headers added by the proxy (token never enters the sandbox)")
			for _, h := range hosts {
				var headers []string
				for _, inj := range p.InjectBindings[h] {
					headers = append(headers, inj.Header)
				}
				sort.Strings(headers)
				pr("      %s: %s\n", h, strings.Join(headers, ", "))
			}
			ln("    ca-trust:   per-run CA bundle in env (SSL_CERT_FILE, CURL_CA_BUNDLE, GIT_SSL_CAINFO, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS)")
		}
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
	case p.UseSeatbelt:
		ln("    method:     seatbelt (sandbox-exec)")
	case p.UsePivotRoot && p.UseLandlock:
		ln("    method:     pivot_root + landlock")
	case p.UsePivotRoot:
		ln("    method:     pivot_root")
	case p.UseLandlock && p.NoUserNS:
		ln("    method:     landlock (no user namespaces)")
	case p.UseLandlock:
		ln("    method:     landlock")
	default:
		ln("    method:     none (env-only)")
	}
	if p.AllowUnixSockets {
		if p.UseSeatbelt {
			ln("    unix:       allowed (--allow-unix-sockets)")
		} else {
			ln("    seccomp:    disabled (--allow-unix-sockets)")
		}
	} else if p.UseSeatbelt {
		ln("    unix:       blocked (seatbelt AF_UNIX deny)")
	} else if p.Caps.Seccomp {
		ln("    seccomp:    AF_UNIX blocked (socket + socketpair)")
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
	plan.EnvSet = config.DefaultEnvVars(tmpDir)
	if len(cfg.Command) > 0 {
		plan.EnvSet["PS1"] = config.DefaultPS1(cfg.Command[0], os.Getenv("NO_COLOR") != "")
	}
	if envRemoveAll {
		plan.EnvSet = make(map[string]string)
		plan.SandboxHome = "" // Suppress HOME fallback in ResolveEnv.
	} else if len(envRemoves) > 0 {
		for _, r := range envRemoves {
			delete(plan.EnvSet, r)
		}
	}
	for _, pair := range cfg.EnvSet {
		k, v, _ := strings.Cut(pair, "=")
		// A "?" prefix on the value makes the assignment conditional: apply it
		// only if k is set in the host environment. Used to placeholder a
		// credential the sandbox would otherwise receive, without introducing
		// one when it is absent (e.g. ANTHROPIC_API_KEY for OAuth users).
		if rest, ok := strings.CutPrefix(v, "?"); ok {
			if _, present := os.LookupEnv(k); !present {
				continue
			}
			v = rest
		}
		// Expand $VAR references against the sandbox env built so far.
		v = os.Expand(v, func(name string) string {
			if val, ok := plan.EnvSet[name]; ok {
				return val
			}
			return ""
		})
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
		// SOCKS5 proxy env vars. Most HTTP clients prefer HTTP_PROXY/HTTPS_PROXY
		// over ALL_PROXY, so HTTP/HTTPS still goes through the HTTP proxy.
		// ALL_PROXY covers non-HTTP tools (curl --socks5, cargo, etc.).
		//
		// Respect a user-provided value (as NO_PROXY does below): set ALL_PROXY
		// empty to suppress the SOCKS env for HTTP-only workloads. httpx eagerly
		// builds a transport for ALL_PROXY at client construction and needs the
		// socks extra otherwise; ssh routing does not use it (setupSSHConfig).
		if plan.SOCKSPort > 0 {
			socksAddr := fmt.Sprintf("127.0.0.1:%d", plan.SOCKSPort)
			socksURL := fmt.Sprintf("socks5h://%s", socksAddr)
			if _, ok := plan.EnvSet["ALL_PROXY"]; !ok {
				plan.EnvSet["ALL_PROXY"] = socksURL
			}
			if _, ok := plan.EnvSet["all_proxy"]; !ok {
				plan.EnvSet["all_proxy"] = socksURL
			}
			plan.EnvSet[SOCKSAddrEnvKey] = socksAddr
		}
	}

	// NO_PROXY: bypass the proxy for localhost so sandbox-internal
	// servers are reachable directly. When HostLoopback is true
	// (--host-loopback), skip this so traffic goes through the proxy
	// to host localhost. Respect user-provided NO_PROXY.
	if plan.ProxyEnabled && !plan.HostLoopback {
		if _, ok := plan.EnvSet["NO_PROXY"]; !ok {
			plan.EnvSet["NO_PROXY"] = defaultNoProxy
		}
		if _, ok := plan.EnvSet["no_proxy"]; !ok {
			plan.EnvSet["no_proxy"] = defaultNoProxy
		}
	}

	// If SSH_AUTH_SOCK is being passed through and the socket exists,
	// add its path to the write list so SSH can communicate with the agent.
	if sockPath := os.Getenv("SSH_AUTH_SOCK"); sockPath != "" {
		if slices.Contains(plan.EnvPassthrough, "SSH_AUTH_SOCK") {
			if _, err := os.Stat(sockPath); err == nil {
				plan.RWFiles = appendUniq(plan.RWFiles, sockPath)
			}
		}
	}
}

// setupSSHConfig writes an SSH config file that routes all connections through
// the SOCKS5 proxy via the _socks-connect helper. SSH does not respect
// ALL_PROXY or any proxy env var, so this is the only way to make bare ssh
// work inside the sandbox.
func setupSSHConfig(plan *SandboxPlan, tmpDir string) error {
	if plan.SOCKSPort == 0 {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil // Best-effort: skip if we can't resolve our own path.
	}

	// Determine the sandbox HOME to find ~/.ssh/config target.
	home := plan.EnvSet["HOME"]
	if home == "" {
		home = tmpDir
	}
	targetConfig := filepath.Join(home, ".ssh", "config")

	// Read the user's existing SSH config (if any) and prepend it so
	// their Host directives take precedence. We can't use Include because
	// we bind-mount over the original file.
	var existing string
	if data, readErr := os.ReadFile(targetConfig); readErr == nil {
		existing = string(data) + "\n"
	}

	content := existing + fmt.Sprintf(`Host *
  ProxyCommand %s _socks-connect %%h %%p
  StrictHostKeyChecking accept-new
`, self)

	// Write to TempDir; the child bind-mounts it over ~/.ssh/config.
	srcDir := filepath.Join(tmpDir, ".ssh")
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		return fmt.Errorf("creating .ssh dir: %w", err)
	}
	srcConfig := filepath.Join(srcDir, "config")
	if err := os.WriteFile(srcConfig, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing ssh config: %w", err)
	}

	// Ensure the target ~/.ssh/config exists so the bind-mount has
	// something to mount over. If HOME is TempDir, srcConfig IS the
	// target and no mount is needed.
	if srcConfig == targetConfig {
		return nil
	}

	// Create target mount point if it doesn't exist.
	if err := os.MkdirAll(filepath.Dir(targetConfig), 0o700); err != nil {
		return fmt.Errorf("creating .ssh dir for mount: %w", err)
	}
	if _, statErr := os.Stat(targetConfig); statErr != nil {
		// Create an empty file as a mount point.
		if err := os.WriteFile(targetConfig, nil, 0o644); err != nil {
			// Non-fatal: the user's home .ssh dir may not be writable.
			return nil
		}
	}

	plan.SSHConfigPath = srcConfig
	plan.SSHConfigDst = targetConfig

	// Expose only the config file (not the whole .ssh directory which
	// contains private keys) so the bind-mount target exists in the
	// mount namespace.
	plan.ROFiles = appendUniq(plan.ROFiles, targetConfig)
	return nil
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
// excludePath is skipped entirely: its parent (e.g. the $TMPDIR base on macOS)
// may contain sensitive user data, and the path itself is already in RWPaths.
func appendExecDirs(roPaths, execPaths []string, excludePath string) []string {
	seen := make(map[string]bool, len(roPaths))
	for _, p := range roPaths {
		seen[p] = true
	}
	for _, p := range execPaths {
		if p == excludePath {
			continue
		}
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
//
// Relative paths are resolved to absolute first. Without this, a relative
// path like "." would reach enforceMountNS where filepath.Join(newRoot, ".")
// collapses to newRoot itself, causing bind-mounts to overwrite the tmpfs
// and leak mount-point stubs onto the host CWD.
func resolveSymlinks(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	var result []string
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			if abs, err := filepath.Abs(p); err == nil {
				p = abs
			}
		}
		if seen[p] {
			continue
		}
		result = append(result, p)
		seen[p] = true
		if resolved, err := filepath.EvalSymlinks(p); err == nil && !seen[resolved] {
			result = append(result, resolved)
			seen[resolved] = true
		}
	}
	return result
}

// buildDegradedPlan creates a plan for platforms where only environment
// sanitization is available. Used by degradedPlanBuilder and tests.
func buildDegradedPlan(cfg *config.Config, caps *Capabilities) (*SandboxPlan, error) {
	plan := &SandboxPlan{Caps: caps}

	if len(cfg.InjectBearer) > 0 || len(cfg.InjectHeader) > 0 {
		return nil, fmt.Errorf("credential injection (--inject-bearer/--inject-header) is only supported on Linux")
	}

	if len(cfg.AllowedDomains) > 0 {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "network filtering",
			Reason: "not supported on this platform",
			Impact: "Network filtering is not available; all network access is unrestricted.",
		})
	}
	if !cfg.NoFSRestrict {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "filesystem restrictions",
			Reason: "not supported on this platform",
			Impact: "Filesystem restrictions are not available; all paths are accessible.",
		})
	}
	if !cfg.NoExecRestrict {
		plan.DegradedLayers = append(plan.DegradedLayers, DegradedLayer{
			Layer:  "executable control",
			Reason: "not supported on this platform",
			Impact: "Executable control is not available; all binaries can be executed.",
		})
	}

	tmpDir, err := createTempDir()
	if err != nil {
		return nil, err
	}
	plan.TempDir = tmpDir
	plan.SandboxHome = resolveSandboxHome(cfg, tmpDir)

	applyEnvPolicy(plan, cfg, tmpDir)
	delete(plan.EnvSet, "IS_SANDBOX")

	plan.Command = cfg.Command
	if err := writeSkill(plan, tmpDir); err != nil {
		return nil, err
	}
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
