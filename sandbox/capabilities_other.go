//go:build !linux && !darwin

package sandbox

import (
	"fmt"
	"runtime"
)

// TUNProbeEnvKey is the environment variable that triggers the TUN probe child.
const TUNProbeEnvKey = "_CURB_TUN_PROBE"

// MountProbeEnvKey is the environment variable that triggers the mount probe child.
const MountProbeEnvKey = "_CURB_MOUNT_PROBE"

// RunTUNProbe is a no-op on non-Linux platforms.
func RunTUNProbe() {}

// RunMountProbe is a no-op on non-Linux platforms.
func RunMountProbe() {}

// ProbeAll on non-Linux returns all capabilities as unavailable.
func ProbeAll() *Capabilities {
	unavailable := fmt.Errorf("not supported on %s", runtime.GOOS)
	return &Capabilities{
		UserNS:  unavailable,
		MountNS: unavailable,
		NetNS:   unavailable,
		TUN:     unavailable,
	}
}
