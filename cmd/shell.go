package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// NewShellCmd creates the "shell" subcommand that launches an interactive
// shell with the "shell" profile auto-applied.
func NewShellCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shell [flags] [-- command [args...]]",
		Short: "Launch an interactive shell with system binaries available",
		Long: `Start an interactive shell inside a sandbox with the "shell" profile,
which allows execution of standard system binaries (/usr/bin, /bin, etc.).

Additional sandbox flags (--read, --write, --domains, etc.) and profiles
(-p git, -p node, etc.) can be combined.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				shell := os.Getenv("SHELL")
				if shell == "" {
					shell = "/bin/sh"
				}
				args = []string{shell}
			}
			return runSandbox(cmd, args, []string{"shell"})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	registerFlags(cmd)
	return cmd
}
