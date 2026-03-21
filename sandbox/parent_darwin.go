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

		// SOCKS5 proxy: real TCP listener.
		if plan.SOCKSPort > 0 {
			socksLn, socksErr := listenProxyPort(plan.SOCKSPort)
			if socksErr != nil {
				return -1, fmt.Errorf("socks5 listener: %w", socksErr)
			}
			defer socksLn.Close()
			socksSrv := buildSOCKS5Server(plan)
			go func() { _ = socksSrv.Serve(socksLn) }()
		}
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

	if err := cmd.Start(); err != nil {
		signal.Stop(sigCh)
		return -1, fmt.Errorf("starting sandbox-exec: %w", err)
	}

	// Forward signals to the child with escalation.
	stopFwd := forwardSignals(sigCh, cmd.Process, hupKillTimeout)

	// Wait for the child to exit.
	waitErr := cmd.Wait()
	stopFwd()
	signal.Stop(sigCh)
	close(sigCh)

	return exitCode(waitErr)
}
