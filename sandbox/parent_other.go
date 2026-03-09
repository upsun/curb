//go:build !linux

package sandbox

import (
	"fmt"
	"runtime"
)

// StartSandbox is not supported on non-Linux platforms.
func StartSandbox(_ *SandboxPlan) (int, error) {
	return -1, fmt.Errorf("sandbox not supported on %s", runtime.GOOS)
}
