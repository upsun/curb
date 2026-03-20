//go:build darwin

package sandbox

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// TUNProbeEnvKey is the environment variable that triggers the TUN probe child.
const TUNProbeEnvKey = "_CURB_TUN_PROBE"

// MountProbeEnvKey is the environment variable that triggers the mount probe child.
const MountProbeEnvKey = "_CURB_MOUNT_PROBE"

// RunTUNProbe is a no-op on macOS.
func RunTUNProbe() {}

// probeTUN is unused on macOS (SetTUN is called instead) but satisfies the
// method reference in Capabilities.TUN().
func (c *Capabilities) probeTUN() error {
	return fmt.Errorf("not supported on %s", runtime.GOOS)
}

// RunMountProbe is a no-op on macOS.
func RunMountProbe() {}

// ProbeAll probes macOS sandbox capabilities.
// On macOS the only kernel sandbox is Seatbelt (sandbox-exec).
// Linux-specific capabilities (user NS, mount NS, etc.) are unavailable.
func ProbeAll() *Capabilities {
	unavailable := fmt.Errorf("not supported on %s", runtime.GOOS)
	caps := &Capabilities{
		UserNS:  unavailable,
		MountNS: unavailable,
		NetNS:   unavailable,
		PidNS:   unavailable,
	}
	caps.SetTUN(unavailable)
	caps.Seatbelt = probeSeatbelt()
	caps.OSVersion = probeOSVersion()
	return caps
}

// probeSeatbelt checks whether /usr/bin/sandbox-exec exists and is executable.
func probeSeatbelt() error {
	_, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return fmt.Errorf("sandbox-exec not found: %w", err)
	}
	return nil
}

// probeOSVersion reads the macOS version via the kern.osproductversion sysctl.
func probeOSVersion() string {
	val, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(val)
}
