//go:build darwin

package sandbox

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
)

// StartSandbox on macOS generates an SBPL profile and spawns the child
// process under sandbox-exec with Seatbelt enforcement.
func StartSandbox(plan *SandboxPlan) (int, error) {
	if !plan.UseSeatbelt {
		return -1, fmt.Errorf("seatbelt enforcement required on macOS")
	}

	// Generate the SBPL profile.
	profile := generateSBPL(plan)

	// Start proxy if enabled.
	var proxySrv *http.Server
	if plan.ProxyEnabled {
		ln, err := listenProxyPort(plan.ProxyPort)
		if err != nil {
			return -1, fmt.Errorf("proxy listener: %w", err)
		}
		defer ln.Close()

		handler := buildProxyHandler(plan)
		proxySrv = &http.Server{Handler: handler}
		go func() { _ = proxySrv.Serve(ln) }()
		defer proxySrv.Close()
	}

	// Build command: sandbox-exec -p '<profile>' -- <command>
	args := []string{"-p", profile, "--"}
	args = append(args, plan.Command...)
	cmd := exec.Command("/usr/bin/sandbox-exec", args...)
	cmd.Env = plan.ResolveEnv()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set up signal forwarding before starting the child.
	sigCh := make(chan os.Signal, 32)
	signal.Notify(sigCh, catchableSignals()...)
	defer signal.Stop(sigCh)

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("starting sandbox-exec: %w", err)
	}

	// Forward signals to the child.
	go func() {
		for sig := range sigCh {
			_ = cmd.Process.Signal(sig)
		}
	}()

	// Wait for the child to exit.
	waitErr := cmd.Wait()
	signal.Stop(sigCh)
	close(sigCh)

	return exitCode(waitErr)
}
