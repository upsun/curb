//go:build !linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// StartSandbox on non-Linux applies environment sanitization only.
// Namespace isolation, filesystem restrictions, and network filtering
// are not available.
func StartSandbox(plan *SandboxPlan) (int, error) {
	for _, d := range plan.DegradedLayers {
		fmt.Fprintf(os.Stderr, "curb: warning: %s: %s\n", d.Layer, d.Reason)
	}

	env := plan.ResolveEnv()

	exe, err := exec.LookPath(plan.Command[0])
	if err != nil {
		return -1, fmt.Errorf("executable %q not found: %w", plan.Command[0], err)
	}

	cmd := exec.Command(exe, plan.Command[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return -1, fmt.Errorf("running command on %s: %w", runtime.GOOS, err)
	}
	return 0, nil
}
