//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/upsun/curb/netstack"
	"github.com/upsun/curb/policy"
)

// StartSandbox re-execs curb inside new namespaces, passes the sandbox config
// to the child via a pipe, and waits for the child to exit.
// It returns the child's exit code, or -1 and an error on setup failure.
func StartSandbox(plan *SandboxPlan) (int, error) {
	// Create config pipe.
	configR, configW, err := os.Pipe()
	if err != nil {
		return -1, fmt.Errorf("creating config pipe: %w", err)
	}

	// Create socketpair for later fd passing (TAP fd in WP07).
	sockParent, sockChild, err := CreateSocketPair()
	if err != nil {
		_ = configR.Close()
		_ = configW.Close()
		return -1, fmt.Errorf("creating socketpair: %w", err)
	}

	// Set up signal forwarding before starting the child to avoid races.
	sigCh := make(chan os.Signal, 32)
	signal.Notify(sigCh, catchableSignals()...)

	// Resolve our own executable path for re-exec.
	// /proc/self/exe is a magic link that some kernels restrict inside user namespaces.
	self, err := os.Executable()
	if err != nil {
		_ = configR.Close()
		_ = configW.Close()
		_ = sockParent.Close()
		_ = sockChild.Close()
		signal.Stop(sigCh)
		return -1, fmt.Errorf("resolving executable path: %w", err)
	}

	// Re-exec curb inside new user, network, and mount namespaces.
	cmd := exec.Command(self)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}
	cmd.Env = []string{InitEnvKey + "=1"}
	cmd.ExtraFiles = []*os.File{configR, sockChild}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		signal.Stop(sigCh)
		_ = configR.Close()
		_ = configW.Close()
		_ = sockParent.Close()
		_ = sockChild.Close()
		return -1, fmt.Errorf("starting sandbox: %w", err)
	}

	// Child has inherited these fds; close our copies.
	_ = configR.Close()
	_ = sockChild.Close()

	// Write config to the pipe.
	cfg := plan.childConfig()
	if err := json.NewEncoder(configW).Encode(&cfg); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		signal.Stop(sigCh)
		_ = configW.Close()
		_ = sockParent.Close()
		return -1, fmt.Errorf("writing config to child: %w", err)
	}
	_ = configW.Close()

	// If network is enabled, receive TAP fd, start netstack, signal child.
	var ns *netstack.Stack
	if plan.NetEnabled {
		abortNet := func() {
			if ns != nil {
				ns.Close()
			}
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			signal.Stop(sigCh)
			_ = sockParent.Close()
		}

		tapFD, recvErr := RecvFD(sockParent)
		if recvErr != nil {
			abortNet()
			return -1, fmt.Errorf("receiving TAP fd: %w", recvErr)
		}
		var filter *netstack.FilterConfig
		if len(plan.AllowedDomains) > 0 {
			matcher := policy.NewDomainMatcher(plan.AllowedDomains, plan.ExactMatch)
			filter = &netstack.FilterConfig{
				Check:      matcher.Match,
				Upstream:   plan.DNSUpstream,
				BlockECH:   plan.BlockECH,
				RequireSNI: plan.RequireSNI,
				AllowHTTP:  plan.AllowHTTP,
			}
		}
		ns, recvErr = netstack.NewStack(tapFD, filter)
		if recvErr != nil {
			abortNet()
			return -1, fmt.Errorf("creating netstack: %w", recvErr)
		}
		if _, recvErr = sockParent.Write([]byte{0}); recvErr != nil {
			abortNet()
			return -1, fmt.Errorf("sending ready signal: %w", recvErr)
		}
	}
	_ = sockParent.Close()

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
	if ns != nil {
		ns.Close()
	}

	if waitErr == nil {
		return 0, nil
	}
	exitErr, ok := waitErr.(*exec.ExitError)
	if !ok {
		return -1, fmt.Errorf("waiting for child: %w", waitErr)
	}

	// Normal exit with non-zero code.
	if code := exitErr.ExitCode(); code >= 0 {
		return code, nil
	}

	// Process killed by signal.
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal()), nil
	}
	return 1, nil
}

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
