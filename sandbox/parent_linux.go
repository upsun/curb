//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/upsun/curb/netstack"
	"github.com/upsun/curb/policy"
	"github.com/upsun/curb/proxy"
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

	// Create socketpair for fd passing (TAP fd or proxy connection fds).
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
	self, err := os.Executable()
	if err != nil {
		_ = configR.Close()
		_ = configW.Close()
		_ = sockParent.Close()
		_ = sockChild.Close()
		signal.Stop(sigCh)
		return -1, fmt.Errorf("resolving executable path: %w", err)
	}

	// Re-exec curb inside new user namespace (and network namespace unless unrestricted).
	cloneFlags := uintptr(syscall.CLONE_NEWUSER)
	if !plan.UnrestrictedNet {
		cloneFlags |= syscall.CLONE_NEWNET
	}
	if plan.UsePivotRoot {
		cloneFlags |= syscall.CLONE_NEWNS
	}
	// PID namespace: skip for proxy-only mode where the child's initLoop
	// handles fork+exec (PID 1 must be the Go runtime for the accept loop).
	proxyOnly := plan.ProxyEnabled && !plan.NetEnabled
	if plan.PidNS && !proxyOnly {
		cloneFlags |= syscall.CLONE_NEWPID
	}
	cmd := exec.Command(self)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: cloneFlags,
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

	// Build proxy handler if proxy is enabled.
	var proxyHandler *proxy.Handler
	if plan.ProxyEnabled {
		proxyHandler = buildProxyHandler(plan)
	}

	// Handle proxy-only mode: receive fds from child, serve them.
	var proxySrv *http.Server
	var proxyListener *proxy.ConnListener
	if plan.ProxyEnabled && !plan.NetEnabled {
		addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: plan.ProxyPort}
		proxyListener = proxy.NewConnListener(addr)
		proxySrv = &http.Server{Handler: proxyHandler}
		go func() { _ = proxySrv.Serve(proxyListener) }()

		// Receive connection fds from child. RecvFD errors are expected on
		// normal shutdown (child exits, socketpair closes). Unexpected errors
		// are indistinguishable here and logged implicitly by the child's
		// SendFD error handling.
		go func() {
			for {
				fd, recvErr := RecvFD(sockParent)
				if recvErr != nil {
					_ = proxyListener.Close()
					return
				}
				f := os.NewFile(uintptr(fd), "proxy-conn")
				conn, fileErr := net.FileConn(f)
				_ = f.Close()
				if fileErr != nil {
					continue
				}
				if enqErr := proxyListener.Enqueue(conn); enqErr != nil {
					_ = conn.Close()
				}
			}
		}()
	}

	// Handle proxy+TUN mode: start proxy on real TCP listener, then netstack.
	var proxyTCPListener net.Listener
	if plan.ProxyEnabled && plan.NetEnabled {
		ln, lnErr := listenProxyPort(plan.ProxyPort)
		if lnErr != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			signal.Stop(sigCh)
			_ = sockParent.Close()
			return -1, fmt.Errorf("proxy listener: %w", lnErr)
		}
		proxyTCPListener = ln
		proxySrv = &http.Server{Handler: proxyHandler}
		go func() { _ = proxySrv.Serve(ln) }()
	}

	// If network (TUN) is enabled, receive TAP fd, start netstack, signal child.
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
		if len(plan.AllowedDomains) > 0 || len(plan.AllowedIPs) > 0 {
			filter = &netstack.FilterConfig{
				ECHMode:        plan.ECHMode,
				RequireSNI:     plan.RequireSNI,
				AllowHTTP:      plan.AllowHTTP,
				AllowLocalhost: plan.AllowLocalhost,
				Logger:         plan.Logger,
			}
			if len(plan.AllowedDomains) > 0 {
				matcher := policy.NewDomainMatcher(plan.AllowedDomains)
				filter.Check = matcher.Match
			} else {
				// IPs-only: deny all domain queries so DNS returns REFUSED.
				filter.Check = func(string) bool { return false }
			}
			if len(plan.AllowedIPs) > 0 {
				ipMatcher := policy.NewIPMatcher(plan.AllowedIPs)
				filter.CheckIP = ipMatcher.Match
			}
		} else if plan.AllowLocalhost {
			filter = &netstack.FilterConfig{
				AllowLocalhost: true,
				Logger:         plan.Logger,
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

	// Close socketpair parent end only when not needed for proxy fd-passing.
	if !plan.ProxyEnabled || plan.NetEnabled {
		_ = sockParent.Close()
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
	if ns != nil {
		ns.Close()
	}

	// Cleanup proxy resources.
	if proxyListener != nil {
		_ = proxyListener.Close()
	}
	if proxyTCPListener != nil {
		_ = proxyTCPListener.Close()
	}
	if proxySrv != nil {
		_ = proxySrv.Close()
	}
	if plan.ProxyEnabled && !plan.NetEnabled {
		_ = sockParent.Close()
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

// buildProxyHandler creates the MITM proxy handler from the sandbox plan.
func buildProxyHandler(plan *SandboxPlan) *proxy.Handler {
	h := &proxy.Handler{
		CertCache: proxy.NewCertCache(plan.CA),
		Logger:    plan.Logger,
		AllowHTTP: plan.AllowHTTP,
	}
	if len(plan.AllowedDomains) > 0 {
		matcher := policy.NewDomainMatcher(plan.AllowedDomains)
		h.DomainCheck = matcher.Match
	}
	if len(plan.AllowedIPs) > 0 {
		ipMatcher := policy.NewIPMatcher(plan.AllowedIPs)
		h.IPCheck = ipMatcher.Match
	}
	return h
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
