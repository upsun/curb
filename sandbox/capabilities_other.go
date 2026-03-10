//go:build !linux

package sandbox

import (
	"fmt"
	"runtime"
)

// TUNProbeEnvKey is the environment variable that triggers the TUN probe child.
const TUNProbeEnvKey = "_CURB_TUN_PROBE"

// RunTUNProbe is a no-op on non-Linux platforms.
func RunTUNProbe() {}

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
