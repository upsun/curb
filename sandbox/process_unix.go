//go:build unix

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// catchableSignals returns all signals that can be caught (1-31, excluding SIGKILL and SIGSTOP).
func catchableSignals() []os.Signal {
	var sigs []os.Signal
	for i := syscall.Signal(1); i <= 31; i++ {
		if i == syscall.SIGKILL || i == syscall.SIGSTOP {
			continue
		}
		sigs = append(sigs, i)
	}
	return sigs
}

// exitCode extracts the exit code from a cmd.Wait() error.
// Returns 0 for nil error, the process exit code, 128+signal for signaled
// processes, or -1 with an error for unexpected failures.
func exitCode(waitErr error) (int, error) {
	if waitErr == nil {
		return 0, nil
	}
	exitErr, ok := waitErr.(*exec.ExitError)
	if !ok {
		return -1, fmt.Errorf("waiting for child: %w", waitErr)
	}
	if code := exitErr.ExitCode(); code >= 0 {
		return code, nil
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal()), nil
	}
	return 1, nil
}
