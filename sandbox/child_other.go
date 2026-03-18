//go:build !linux && !darwin

package sandbox

import (
	"os"

	"github.com/upsun/curb/clog"
)

// ChildInit is not supported on non-Linux platforms.
func ChildInit() {
	clog.Errorf("sandboxing is not supported on this platform")
	os.Exit(ExitSetupFailure)
}
