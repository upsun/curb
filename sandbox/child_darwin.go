//go:build darwin

package sandbox

import (
	"os"

	"github.com/upsun/curb/clog"
)

// ChildInit on macOS is a no-op. Seatbelt enforcement is applied at spawn time
// by sandbox-exec, not via re-exec.
func ChildInit() {
	clog.Errorf("unexpected _CURB_INIT on macOS: re-exec is not used")
	os.Exit(ExitSetupFailure)
}
