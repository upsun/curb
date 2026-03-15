package cmd

import (
	"fmt"
	"os"
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
		Short: "Sandbox a process with filesystem, network, and environment restrictions",
		Long: `curb runs a command inside an unprivileged sandbox with:
  - Filesystem restrictions (Landlock + mount namespace)
  - Network filtering by domain (--domains) or IP (--ips) via userspace TCP/IP
  - Unrestricted network pass-through (--unrestricted-net) with FS sandbox only
  - Executable control (Landlock EXECUTE)
  - Environment sanitization (deny-by-default)

Use -- before the command when it has its own flags.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.FromFlags(cmd)
			if err != nil {
				return err
			}
			config.MergeEnv(cfg, cmd)
			cfg.Command = args
			if len(cfg.Command) == 0 {
				shell := os.Getenv("SHELL")
				if shell == "" {
					shell = "/bin/sh"
				}
				cfg.Command = []string{shell}
			}

			logger, logErr := clog.New(cfg.LogFile, cfg.Verbose, cfg.Debug, cfg.Quiet)
			if logErr != nil {
				return logErr
			}
			defer logger.Close()

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
			plan, err := sandbox.BuildPlan(cfg, caps)
			if err != nil {
				return err
			}
			defer plan.Cleanup()
			plan.Logger = logger

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
			} else if (plan.NetEnabled || plan.ProxyEnabled) && (len(plan.AllowedDomains) > 0 || len(plan.AllowedIPs) > 0) {
				var parts []string
				if len(plan.AllowedDomains) > 0 {
					parts = append(parts, "domains: "+strings.Join(plan.AllowedDomains, ", "))
				}
				if len(plan.AllowedIPs) > 0 {
					parts = append(parts, "IPs: "+strings.Join(plan.AllowedIPs, ", "))
				}
				logger.Info("net: allowed %s.", strings.Join(parts, "; "))
			} else if plan.NetEnabled || plan.ProxyEnabled {
				logger.Info("net: localhost only.")
			} else {
				logger.Info("net: disabled (no --domains or --ips).")
			}
			if plan.PidNS {
				logger.Info("pid: isolated.")
			} else {
				logger.Info("pid: unavailable (no PID namespace).")
			}
			if plan.NoFSRestrict {
				logger.Info("fs: disabled (--write '*').")
			} else {
				switch {
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
			if err != nil {
				logger.Error("%v", err)
				os.Exit(sandbox.ExitSetupFailure)
			}
			os.Exit(exitCode)
			return nil // Unreachable.
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	registerFlags(cmd)
	return cmd
}

func registerFlags(cmd *cobra.Command) {
	f := cmd.Flags()

	// Network filtering.
	f.StringSlice("domains", nil, "allowed domain patterns (e.g. example.com, *.github.com)")
	f.StringSlice("ips", nil, "allowed IP addresses or CIDR ranges (e.g. 10.0.0.1, 192.168.0.0/16, ::1)")
	f.Bool("unrestricted-net", false, "allow unrestricted network access (no filtering)")
	f.String("proxy", "on", "MITM proxy for HTTP/HTTPS filtering: on, off")
	f.String("tun", "auto", "TUN/TAP netstack layer: auto, always")

	// Filesystem (supports glob patterns and ! exclusions).
	f.StringSlice("read", nil, "readable paths (! prefix denies/hides, '!*' clears all)")
	f.StringSlice("write", nil, "writable paths (! prefix makes read-only, '*' disables FS)")

	// Executable control.
	f.StringSlice("exec", nil, "allowed executables (! prefix removes defaults, '*' allows all)")

	// Environment.
	f.StringSlice("env", nil, "env vars to pass/set (! prefix removes defaults, '*' for all)")

	// Network options.
	f.String("ech", "strip", "ECH handling mode: strip, allow, deny")
	f.Bool("allow-no-sni", false, "allow TLS connections without SNI (reduces filtering)")
	f.Bool("allow-http", false, "allow plaintext HTTP when domain filtering is active")

	// Logging.
	f.String("log-file", "", "write structured JSON logs to file")
	f.BoolP("verbose", "v", false, "verbose output")
	f.Bool("debug", false, "detailed netstack/relay debug logging (implies -v)")
	f.BoolP("quiet", "q", false, "suppress warnings")

	// Other.
	f.Bool("dry-run", false, "print the sandbox plan without running the command")
	f.String("home", "", "set HOME environment variable for the sandboxed process")
}
