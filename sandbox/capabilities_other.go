//go:build !linux

package sandbox

import (
	"fmt"
	"runtime"
)

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
