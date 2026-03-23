//go:build !linux && !darwin

package sandbox

import (
	"fmt"
	"runtime"
)

// MountProbeEnvKey is the environment variable that triggers the mount probe child.
const MountProbeEnvKey = "_CURB_MOUNT_PROBE"

// RunMountProbe is a no-op on non-Linux platforms.
func RunMountProbe() {}

// ProbeAll on unsupported platforms returns all capabilities as unavailable.
func ProbeAll() *Capabilities {
	unavailable := fmt.Errorf("not supported on %s", runtime.GOOS)
	return &Capabilities{
		UserNS:  unavailable,
		MountNS: unavailable,
		NetNS:   unavailable,
	}
}
