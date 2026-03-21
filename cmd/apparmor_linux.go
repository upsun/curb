//go:build linux

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"
)

// profilePathRe validates that a binary path contains only safe characters for AppArmor profiles.
var profilePathRe = regexp.MustCompile(`^[a-zA-Z0-9/_.-]+$`)

// NewApparmorCmd creates the "apparmor" subcommand with view/install subcommands.
func NewApparmorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apparmor",
		Short: "Manage the AppArmor profile for curb",
		Long: `Manage the AppArmor profile that allows curb to use unprivileged
user namespaces on Ubuntu 24.04+.

  curb apparmor            Print the profile to stdout (same as "view").
  curb apparmor view       Print the profile to stdout.
  curb apparmor install    Write and load the profile (requires root).`,
	}
	cmd.PersistentFlags().String("path", "", "absolute path to the curb binary (default: auto-detect)")

	viewCmd := &cobra.Command{
		Use:   "view",
		Short: "Print the AppArmor profile to stdout",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			binPath, _ := cmd.Flags().GetString("path")
			return runApparmorView(binPath)
		},
	}

	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Write and load the AppArmor profile (requires root)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			binPath, _ := cmd.Flags().GetString("path")
			return runApparmorInstall(binPath)
		},
	}

	cmd.AddCommand(viewCmd, installCmd)

	// Default to "view" when no subcommand is given.
	cmd.RunE = viewCmd.RunE

	return cmd
}

const profilePath = "/etc/apparmor.d/curb"

// generateProfile returns the AppArmor profile for the given binary path.
// The attachment uses alternation to also cover a "curb-test" binary built
// by integration tests (go test ./sandbox/).
func generateProfile(binPath string) string {
	return fmt.Sprintf(`abi <abi/4.0>,

include <tunables/global>

profile curb %s{,-test} flags=(attach_disconnected) {
  include <abstractions/base>

  # Allow user namespace creation.
  userns,

  # Mount operations inside user namespaces (pivot_root enforcement).
  capability sys_admin,
  mount,
  umount,
  pivot_root,

  # Network interface configuration and TAP device (--domains).
  capability net_admin,
  network,

  # Profile management (apparmor_parser -r during "curb apparmor install").
  capability mac_admin,

  # Signal delivery between parent/child across namespaces.
  signal,

  # curb needs broad host file access for sandbox setup (bind mounts).
  # The sandboxed child is restricted by the namespace, not AppArmor.
  /** rwlkmix,
  /dev/net/tun rw,
  /proc/** rw,
  /sys/** r,

  # devpts nodes appear as disconnected paths in user namespaces.
  owner /dev/pts/[0-9]* rw,
}
`, binPath)
}

func resolveBinPath(binPath string) (string, error) {
	if binPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("cannot detect binary path: %w (use --path)", err)
		}
		resolved, err := filepath.EvalSymlinks(exe)
		if err != nil {
			return "", fmt.Errorf("cannot resolve binary path: %w (use --path)", err)
		}
		binPath = resolved
	}
	if !filepath.IsAbs(binPath) {
		return "", fmt.Errorf("--path must be absolute: %s", binPath)
	}
	if !profilePathRe.MatchString(binPath) {
		return "", fmt.Errorf("--path contains unsupported characters; AppArmor profile paths must use only [a-zA-Z0-9/_.-]")
	}
	return binPath, nil
}

func runApparmorView(binPath string) error {
	binPath, err := resolveBinPath(binPath)
	if err != nil {
		return err
	}
	fmt.Print(generateProfile(binPath))
	fmt.Fprintln(os.Stderr, "# To install, run:")
	fmt.Fprintf(os.Stderr, "#   sudo curb apparmor install --path %s\n", binPath)
	return nil
}

func runApparmorInstall(binPath string) error {
	binPath, err := resolveBinPath(binPath)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("install requires root; run: sudo curb apparmor install")
	}

	if err := os.WriteFile(profilePath, []byte(generateProfile(binPath)), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", profilePath, err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s\n", profilePath)

	loadCmd := exec.Command("apparmor_parser", "-r", profilePath)
	out, err := loadCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apparmor_parser -r %s failed: %w\n%s", profilePath, err, out)
	}
	fmt.Fprintln(os.Stderr, "Profile loaded.")
	return nil
}
