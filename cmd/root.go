package cmd

import (
	"fmt"
	"os"
	"runtime/trace"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/upsun/curb/clog"
	"github.com/upsun/curb/config"
	"github.com/upsun/curb/sandbox"
)

// NewRootCmd creates the curb root command.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "curb [flags] [--] [command [args...]]",
		Short: "curb puts a command in a sandbox, restricting its capabilities by default.",
		Long: `curb puts a command in a sandbox, restricting its capabilities by default.

` + longDescription + `

Use -- before the command when it has its own flags.`,
		Example: `  curb make test                                            # default sandbox
  curb --domains example.com -- curl https://example.com    # allow specific domains
  curb -p node -w . -- npm install                          # profile + writable cwd
  curb -a cargo build                                       # auto-select profile
  curb --dry-run -p node -- npm install                     # preview sandbox plan`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				// Show short description + usage (not the full --help details).
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), boldFirst(cmd.Short))
				_, _ = fmt.Fprintln(cmd.OutOrStdout())
				return cmd.Usage()
			}
			return runSandbox(cmd, args, nil)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	registerFlags(cmd)
	annotateFlags(cmd.Flags())
	applyHelpTemplate(cmd)
	cmd.AddCommand(NewProfileCmd())
	cmd.AddCommand(NewApparmorCmd())
	cmd.AddCommand(NewSocksConnectCmd())
	return cmd
}

// runSandbox is the shared sandbox launch logic used by the root command and subcommands.
// extraProfiles are prepended to the profile list before merging.
func runSandbox(cmd *cobra.Command, args []string, extraProfiles []string) error {
	if traceFile, _ := cmd.Flags().GetString("trace"); traceFile != "" {
		f, err := os.Create(traceFile)
		if err != nil {
			return fmt.Errorf("trace: %w", err)
		}
		defer func() { _ = f.Close() }()
		if err := trace.Start(f); err != nil {
			return fmt.Errorf("trace: %w", err)
		}
		defer trace.Stop()
	}

	cfg, err := config.FromFlags(cmd)
	if err != nil {
		return err
	}
	cfs, paths, cfErr := resolveConfigFiles(cmd)
	if cfErr != nil {
		return cfErr
	}

	// Collect activated profiles from config files, --profile flag, and CURB_PROFILES.
	profileNames := collectProfiles(cmd, cfs)
	profileNames = append(extraProfiles, profileNames...)

	// Determine whether auto-profile matching is enabled.
	// Check all three sources early (MergeEnv runs later).
	autoEnabled := cfg.Auto
	if !autoEnabled {
		autoEnabled = config.EnvBool("CURB_AUTO")
	}
	if !autoEnabled {
		for _, cf := range cfs {
			if cf.Auto != nil && *cf.Auto {
				autoEnabled = true
				break
			}
		}
	}

	// Auto-profile: match command name to a profile's commands list.
	var autoProfile, autoHint string
	var matchErrs []error
	if len(args) > 0 {
		matched, ok, errs := config.MatchProfile(args[0])
		matchErrs = errs
		if ok && autoEnabled {
			autoProfile = matched
			if !slices.Contains(profileNames, matched) {
				profileNames = append([]string{matched}, profileNames...)
			}
		} else if ok && !autoEnabled && !slices.Contains(profileNames, matched) {
			autoHint = matched
		}
	}

	if err := config.MergeProfiles(cfg, profileNames, cmd.Flags()); err != nil {
		return err
	}

	// Config files override profiles.
	for _, cf := range cfs {
		config.MergeConfigFile(cfg, cf, cmd.Flags())
	}
	cfg.ConfigFilePaths = paths
	config.MergeEnv(cfg, cmd)
	cfg.Command = args

	logger, logErr := clog.New(cfg.LogFile, cfg.Verbose, cfg.Debug, cfg.Quiet)
	if logErr != nil {
		return logErr
	}
	defer logger.Close()

	for _, p := range cfg.ConfigFilePaths {
		logger.Info("config: loaded %s.", p)
	}
	for _, e := range matchErrs {
		logger.Warn("auto: %v.", e)
	}
	if autoProfile != "" {
		logger.Info("auto: matched profile %q for %q.", autoProfile, args[0])
	} else if autoEnabled && len(args) > 0 {
		logger.Info("auto: no profile matched for %q.", args[0])
	}
	if autoHint != "" {
		logger.Hint("use %s to auto-apply the %s profile for %s.", logger.Code("-a"), logger.Code(autoHint), logger.Code(args[0]))
	}
	if len(profileNames) > 0 {
		logger.Info("profiles: %s.", strings.Join(profileNames, ", "))
	}

	if cfg.EnvPassthroughAll {
		logger.Warn("Entire host environment passed to child (--env '*').")
	}

	caps := sandbox.ProbeAll()
	// Testing hooks: disable enforcement layers to exercise each path in isolation.
	if os.Getenv(sandbox.TestNoLandlockEnvKey) == "1" {
		caps.LandlockABI = 0
	}
	if os.Getenv(sandbox.TestNoMountNSEnvKey) == "1" {
		caps.MountNS = fmt.Errorf("disabled by %s", sandbox.TestNoMountNSEnvKey)
	}
	if os.Getenv(sandbox.TestNoUserNSEnvKey) == "1" {
		caps.UserNS = fmt.Errorf("disabled by %s", sandbox.TestNoUserNSEnvKey)
	}
	if os.Getenv(sandbox.TestNoSeccompEnvKey) == "1" {
		caps.Seccomp = false
	}
	plan, err := sandbox.BuildPlan(cfg, caps, logger)
	if err != nil {
		return err
	}
	defer plan.Cleanup()

	if cfg.DryRun {
		plan.PrintDryRun(os.Stderr)
		return nil
	}

	// Startup summary.
	if plan.ProxyEnabled {
		logger.Info("proxy: on (127.0.0.1:%d).", plan.ProxyPort)
	}
	if plan.UnrestrictedNet {
		logger.Info("net: unrestricted (--unrestricted-net).")
	} else if plan.ProxyEnabled && (len(plan.AllowedDomains) > 0 || len(plan.AllowedIPs) > 0) {
		var parts []string
		if len(plan.AllowedDomains) > 0 {
			parts = append(parts, "domains: "+strings.Join(plan.AllowedDomains, ", "))
		}
		if len(plan.AllowedIPs) > 0 {
			parts = append(parts, "IPs: "+strings.Join(plan.AllowedIPs, ", "))
		}
		logger.Info("net: allowed %s.", strings.Join(parts, "; "))
	} else if plan.ProxyEnabled && plan.HostLoopback {
		logger.Info("net: host localhost only (--host-loopback).")
	} else if plan.ProxyEnabled {
		logger.Info("net: sandbox-internal localhost only.")
	} else {
		logger.Info("net: disabled (no --domains or --ips).")
	}
	if plan.PidNS {
		logger.Info("pid: isolated.")
	} else if !plan.UseSeatbelt {
		logger.Info("pid: unavailable (no PID namespace).")
	}
	if plan.NoFSRestrict {
		logger.Info("fs: disabled (--write '*').")
	} else {
		switch {
		case plan.UseSeatbelt:
			logger.Info("fs: active (seatbelt).")
		case plan.UsePivotRoot && plan.UseLandlock:
			logger.Info("fs: active (pivot_root + landlock).")
		case plan.UsePivotRoot:
			logger.Info("fs: active (pivot_root).")
		case plan.UseLandlock:
			logger.Info("fs: active (landlock; mount namespaces unavailable).")
		}
	}
	if cfg.NoExecRestrict {
		logger.Info("exec: disabled (--exec '*').")
	} else {
		logger.Info("exec: active.")
	}
	if plan.AllowUnixSockets {
		if plan.UseSeatbelt {
			logger.Info("unix sockets: allowed (--allow-unix-sockets).")
		} else {
			logger.Info("seccomp: disabled (--allow-unix-sockets).")
		}
	} else if plan.UseSeatbelt {
		logger.Info("unix sockets: blocked (seatbelt).")
	} else if caps.Seccomp {
		logger.Info("seccomp: AF_UNIX blocked.")
	}
	if cfg.EnvPassthroughAll {
		logger.Info("env: full host passthrough.")
	} else {
		logger.Info("env: deny-by-default.")
	}
	for _, d := range plan.DegradedLayers {
		logger.Warn("%s: %s", d.Layer, d.Impact)
	}

	exitCode, err := sandbox.StartSandbox(plan)
	plan.Cleanup()
	// Stop tracing before os.Exit (which skips defers).
	trace.Stop()
	if err != nil {
		logger.Error("%v", err)
		os.Exit(sandbox.ExitSetupFailure)
	}
	os.Exit(exitCode)
	return nil // Unreachable.
}

// resolveConfigFiles loads config files in merge order:
// 1. -c/--config-file flags (can repeat; merged left to right).
// 2. CURB_CONFIG_FILE env var (if -c not set).
// 3. Auto-discovery: walk up from CWD for .curb.yaml (if neither -c nor CURB_CONFIG_FILE is set).
func resolveConfigFiles(cmd *cobra.Command) ([]*config.ConfigFile, []string, error) {
	var paths []string
	explicit, _ := cmd.Flags().GetStringSlice("config-file")
	if len(explicit) > 0 {
		paths = explicit
	} else if envVal, ok := os.LookupEnv("CURB_CONFIG_FILE"); ok && envVal != "" {
		paths = []string{envVal}
	} else if found := config.FindConfigFile(); found != "" {
		paths = []string{found}
	}
	var files []*config.ConfigFile
	for _, p := range paths {
		cf, err := config.LoadConfigFile(p)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, cf)
	}
	return files, paths, nil
}

// collectProfiles gathers and deduplicates profile names from config files, --profiles flag, and CURB_PROFILES env.
func collectProfiles(cmd *cobra.Command, cfs []*config.ConfigFile) []string {
	var all []string
	// 1. Config files (lowest priority for profile activation).
	for _, cf := range cfs {
		all = append(all, cf.Profiles...)
	}
	// 2. --profile flag.
	if flagProfiles, _ := cmd.Flags().GetStringSlice("profiles"); len(flagProfiles) > 0 {
		all = append(all, flagProfiles...)
	}
	// 3. CURB_PROFILES env var.
	if val, ok := os.LookupEnv("CURB_PROFILES"); ok && val != "" {
		all = append(all, config.SplitComma(val)...)
	}
	// Deduplicate while preserving order.
	seen := make(map[string]bool)
	names := all[:0]
	for _, n := range all {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return names
}

func registerFlags(cmd *cobra.Command) {
	f := cmd.Flags()

	// Config file.
	f.StringSliceP("config-file", "c", nil, "config file path(s) (default: auto-discover .curb.yaml)")

	// Profiles.
	f.StringSliceP("profiles", "p", nil, "activate named profiles (e.g. node,git)")
	f.BoolP("auto", "a", false, "auto-select a profile matching the command name")

	// Filesystem.
	f.StringSliceP("read", "r", nil, "readable paths (default: system dirs + cwd)")
	f.StringSliceP("write", "w", nil, "writable paths (default: none)")

	// Network.
	f.StringSlice("domains", nil, "allowed domain patterns (e.g. example.com, *.github.com)")
	f.StringSlice("ips", nil, "allowed IP/CIDR ranges (e.g. 10.0.0.1, 192.168.0.0/16)")
	f.Bool("unrestricted-net", false, "skip network restrictions entirely")
	f.Bool("host-loopback", false, "forward localhost traffic to host loopback")

	// Executables.
	f.StringSlice("exec", nil, "allowed executables (default: invoked command only)")

	// Environment.
	f.StringSlice("env", nil, "env vars to pass (NAME) or set (NAME=VALUE)")

	// Network options.
	f.Bool("allow-unix-sockets", false, "allow AF_UNIX sockets (Docker, DB sockets)")

	// Output.
	f.Bool("dry-run", false, "print sandbox plan without running")
	f.BoolP("verbose", "v", false, "verbose output")
	f.Bool("debug", false, "detailed proxy/relay debug logging (implies -v)")
	f.BoolP("quiet", "q", false, "suppress warnings")
	f.String("log-file", "", "write JSON logs to file")

	// Profiling (hidden).
	f.String("trace", "", "write execution trace to file (view with: go tool trace FILE)")
	_ = f.MarkHidden("trace")
}
