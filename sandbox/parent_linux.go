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

// resources is a stack-based cleanup manager. Closers run in LIFO order.
type resources struct{ closers []func() }

func (r *resources) push(fn func()) { r.closers = append(r.closers, fn) }

func (r *resources) closeAll() {
	for i := len(r.closers) - 1; i >= 0; i-- {
		r.closers[i]()
	}
	r.closers = nil
}

// StartSandbox re-execs curb inside new namespaces, passes the sandbox config
// to the child via a pipe, and waits for the child to exit.
// It returns the child's exit code, or -1 and an error on setup failure.
func StartSandbox(plan *SandboxPlan) (int, error) {
	if plan.NoUserNS {
		return startLandlockOnly(plan)
	}
	var res resources

	// Create config pipe.
	configR, configW, err := os.Pipe()
	if err != nil {
		return -1, fmt.Errorf("creating config pipe: %w", err)
	}
	res.push(func() { _ = configR.Close() })
	res.push(func() { _ = configW.Close() })

	// Create socketpair for fd passing (TAP fd or proxy connection fds).
	sockParent, sockChild, err := CreateSocketPair()
	if err != nil {
		res.closeAll()
		return -1, fmt.Errorf("creating socketpair: %w", err)
	}
	res.push(func() { _ = sockParent.Close() })
	res.push(func() { _ = sockChild.Close() })

	// Set up signal forwarding before starting the child to avoid races.
	sigCh := make(chan os.Signal, 32)
	signal.Notify(sigCh, catchableSignals()...)
	res.push(func() { signal.Stop(sigCh) })

	// Resolve our own executable path for re-exec.
	self, err := os.Executable()
	if err != nil {
		res.closeAll()
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
		res.closeAll()
		return -1, fmt.Errorf("starting sandbox: %w", err)
	}

	// abort kills the child and cleans up all resources. Used on error paths
	// after cmd.Start() succeeds.
	abort := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		res.closeAll()
	}

	// Child has inherited these fds; close our copies.
	_ = configR.Close()
	_ = sockChild.Close()

	// Write config to the pipe.
	cfg := plan.childConfig()
	if err := json.NewEncoder(configW).Encode(&cfg); err != nil {
		abort()
		return -1, fmt.Errorf("writing config to child: %w", err)
	}
	_ = configW.Close()

	// Start proxy if enabled.
	var proxySrv *http.Server
	if plan.ProxyEnabled {
		handler := buildProxyHandler(plan)

		if !plan.NetEnabled {
			// Proxy-only: ConnListener fed by recvFDLoop.
			addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: plan.ProxyPort}
			cl := proxy.NewConnListener(addr)
			res.push(func() { _ = cl.Close() })
			proxySrv = startProxyServer(cl, handler)
			go recvFDLoop(sockParent, cl)
		} else {
			// Proxy+TUN: real TCP listener reachable via netstack localhost forwarding.
			ln, lnErr := listenProxyPort(plan.ProxyPort)
			if lnErr != nil {
				abort()
				return -1, fmt.Errorf("proxy listener: %w", lnErr)
			}
			res.push(func() { _ = ln.Close() })
			proxySrv = startProxyServer(ln, handler)
		}
		res.push(func() { _ = proxySrv.Close() })
	}

	// If network (TUN) is enabled, receive TAP fd, start netstack, signal child.
	if plan.NetEnabled {
		tapFD, recvErr := RecvFD(sockParent)
		if recvErr != nil {
			abort()
			return -1, fmt.Errorf("receiving TAP fd: %w", recvErr)
		}
		filter := buildNetstackFilter(plan)
		ns, recvErr := netstack.NewStack(tapFD, filter)
		if recvErr != nil {
			abort()
			return -1, fmt.Errorf("creating netstack: %w", recvErr)
		}
		res.push(func() { ns.Close() })
		if _, recvErr = sockParent.Write([]byte{0}); recvErr != nil {
			abort()
			return -1, fmt.Errorf("sending ready signal: %w", recvErr)
		}
	}

	// Close socketpair parent end when not needed for proxy fd-passing.
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
	res.closeAll()

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

// startProxyServer creates an HTTP server and starts serving in a goroutine.
func startProxyServer(ln net.Listener, handler *proxy.Handler) *http.Server {
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	return srv
}

// recvFDLoop receives connection fds from the child over the socketpair and
// enqueues them into the ConnListener for the proxy server. It returns when
// the socketpair closes (normal shutdown) or on any RecvFD error.
func recvFDLoop(sock *os.File, cl *proxy.ConnListener) {
	for {
		fd, err := RecvFD(sock)
		if err != nil {
			_ = cl.Close()
			return
		}
		f := os.NewFile(uintptr(fd), "proxy-conn")
		conn, fileErr := net.FileConn(f)
		_ = f.Close()
		if fileErr != nil {
			continue
		}
		if enqErr := cl.Enqueue(conn); enqErr != nil {
			_ = conn.Close()
		}
	}
}

// buildNetstackFilter constructs the netstack filter configuration from the plan.
func buildNetstackFilter(plan *SandboxPlan) *netstack.FilterConfig {
	if len(plan.AllowedDomains) > 0 || len(plan.AllowedIPs) > 0 {
		filter := &netstack.FilterConfig{
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
		return filter
	}
	if plan.AllowLocalhost {
		return &netstack.FilterConfig{
			AllowLocalhost: true,
			Logger:         plan.Logger,
		}
	}
	return nil
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

// startLandlockOnly applies FS enforcement and exec's the target command
// directly. Used when user namespaces are unavailable. When plan.NoUserNS
// is true, resolveCapabilities sets UsePivotRoot=false and UseLandlock=true,
// so enforceFS naturally applies only Landlock.
func startLandlockOnly(plan *SandboxPlan) (int, error) {
	cfg := plan.childConfig()
	if err := enforceFS(&cfg); err != nil {
		return -1, err
	}
	if err := enforceSeccomp(cfg.AllowUnixSockets); err != nil {
		return -1, err
	}
	exe, err := findExecutable(cfg.Command[0], cfg.Env)
	if err != nil {
		return -1, err
	}
	// Do not call plan.Cleanup() here: TempDir contains shell init files
	// (.curb.bashrc, .zshrc) that the exec'd process needs to read.
	// The OS reclaims the directory when the process exits.
	return -1, syscall.Exec(exe, cfg.Command, cfg.Env)
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
