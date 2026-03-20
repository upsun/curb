//go:build !linux

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewApparmorCmd creates a stub "apparmor" subcommand for non-Linux platforms.
func NewApparmorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "apparmor",
		Short: "Manage the AppArmor profile for curb",
		Args:  cobra.ArbitraryArgs,
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("apparmor is only available on Linux")
		},
	}
}
