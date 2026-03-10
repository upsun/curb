package cmd

import (
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
		Use:   "curb [flags] [--] command [args...]",
		Short: "Sandbox a process with filesystem, network, and environment restrictions",
		Long: `curb runs a command inside an unprivileged sandbox with:
  - Filesystem restrictions (Landlock + mount namespace)
  - Domain-level network filtering (userspace TCP/IP)
  - Executable control (Landlock EXECUTE)
  - Environment sanitization (deny-by-default)

Use -- before the command when it has its own flags.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_ = cmd.Help()
				os.Exit(0)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.FromFlags(cmd)
			if err != nil {
				return err
			}
			config.MergeEnv(cfg, cmd)
			cfg.Command = args

			logger, logErr := clog.New(cfg.LogFile, cfg.Verbose, cfg.Quiet)
			if logErr != nil {
				return logErr
			}
			defer logger.Close()

			if cfg.EnvPassthroughAll {
				logger.Warn("Entire host environment passed to child (--allow-env '*').")
			}

			caps := sandbox.ProbeAll()
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
			if plan.NetEnabled && len(plan.AllowedDomains) > 0 {
				logger.Info("net: allowed domains: %s.", strings.Join(plan.AllowedDomains, ", "))
			} else if plan.NetEnabled {
				logger.Info("net: localhost only.")
			} else {
				logger.Info("net: disabled (no --allow-domains).")
			}
			if plan.NoFSRestrict {
				logger.Info("fs: disabled (--allow-write '*').")
			} else {
				logger.Info("fs: active.")
			}
			if cfg.NoExecRestrict {
				logger.Info("exec: disabled (--allow-exec '*').")
			} else {
				logger.Info("exec: active.")
			}
			if cfg.EnvPassthroughAll {
				logger.Info("env: full host passthrough.")
			} else {
				logger.Info("env: deny-by-default.")
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

	// Domain filtering.
	f.StringSlice("allow-domains", nil, "allowed domain patterns (e.g. example.com, *.github.com)")

	// Filesystem (supports glob patterns, e.g. ~/projects/*.md).
	f.StringSlice("allow-read", nil, "additional readable paths (use '*' to allow all reads)")
	f.StringSlice("allow-write", nil, "additional writable paths (use '*' to disable all FS restrictions)")
	f.StringSlice("hide", nil, "paths to hide from the child process")

	// Executable control.
	f.StringSlice("allow-exec", nil, "additional allowed executables (use '*' to allow all)")

	// Environment.
	f.StringSlice("allow-env", nil, "env vars to pass through (NAME) or set (NAME=VALUE) (use '*' for all)")

	// Network options.
	f.Bool("allow-localhost", false, "allow child to reach host services via localhost")
	f.Bool("allow-ech", false, "allow TLS Encrypted Client Hello (reduces filtering)")
	f.Bool("allow-no-sni", false, "allow TLS connections without SNI (reduces filtering)")
	f.Bool("allow-http", false, "allow plaintext HTTP when domain filtering is active")

	// Logging.
	f.String("log-file", "", "write structured JSON logs to file")
	f.BoolP("verbose", "v", false, "verbose output")
	f.BoolP("quiet", "q", false, "suppress warnings")

	// Other.
	f.Bool("dry-run", false, "print the sandbox plan without running the command")
	f.String("home", "", "custom writable home directory path")
}
