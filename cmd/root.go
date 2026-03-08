package cmd

import (
	"fmt"

	"github.com/platformsh/curb/config"
	"github.com/spf13/cobra"
)

// NewRootCmd creates the curb root command.
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "curb [flags] -- command [args...]",
		Short: "Sandbox a process with filesystem, network, and environment restrictions",
		Long: `curb runs a command inside an unprivileged sandbox with:
  - Filesystem restrictions (Landlock + mount namespace)
  - Domain-level network filtering (userspace TCP/IP)
  - Executable control (Landlock EXECUTE)
  - Environment sanitization (deny-by-default)

The target command must follow a -- separator.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("requires a command after -- separator")
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

			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "curb: sandbox not yet implemented")
			return nil
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
	f.StringSlice("allow", nil, "allowed domain patterns (e.g. example.com, *.github.com)")
	f.String("allow-file", "", "file containing allowed domains (one per line)")

	// Filesystem.
	f.StringSlice("ro", nil, "additional read-only paths")
	f.StringSlice("rw", nil, "additional read-write paths")
	f.StringSlice("hide", nil, "paths to hide from the child process")

	// Executable control.
	f.StringSlice("exec", nil, "additional allowed executables")

	// Environment.
	f.StringSlice("env", nil, "env vars to pass through (NAME) or set (NAME=VALUE)")
	f.Bool("env-passthrough", false, "pass through the entire host environment")

	// Escape hatches.
	f.Bool("no-fs-restrict", false, "disable filesystem restrictions")
	f.Bool("no-exec-restrict", false, "disable executable restrictions")

	// Network options.
	f.Bool("allow-localhost", false, "allow child to reach host services via localhost")
	f.Bool("unsafe-allow-ech", false, "allow TLS Encrypted Client Hello (reduces filtering)")
	f.Bool("unsafe-allow-no-sni", false, "allow TLS connections without SNI (reduces filtering)")
	f.Bool("unsafe-allow-http", false, "allow plaintext HTTP when domain filtering is active")
	f.Bool("exact-match", false, "disable subdomain matching for allowed domains")
	f.String("dns-upstream", "", "upstream DNS resolver address")

	// Logging.
	f.Bool("log-blocked", true, "log blocked access attempts to stderr")
	f.Bool("log-allowed", false, "log allowed access to stderr")
	f.BoolP("verbose", "v", false, "verbose output")

	// Other.
	f.Bool("dry-run", false, "print the sandbox plan without running the command")
	f.String("home", "", "custom writable home directory path")
}
