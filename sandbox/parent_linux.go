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
	if plan.PidNS {
		cloneFlags |= syscall.CLONE_NEWPID
	}
	cmd := exec.Command(self)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: cloneFlags,
		Pdeathsig:  syscall.SIGKILL,
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

		// ConnListeners fed by recvFDLoop (child relays accepted fds to parent).
		httpAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: plan.ProxyPort}
		httpCL := proxy.NewConnListener(httpAddr)
		res.push(func() { _ = httpCL.Close() })
		proxySrv = startProxyServer(httpCL, handler)

		// SOCKS5 proxy: separate ConnListener dispatched by tag.
		var socksCL *proxy.ConnListener
		if plan.SOCKSPort > 0 {
			socksAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: plan.SOCKSPort}
			socksCL = proxy.NewConnListener(socksAddr)
			res.push(func() { _ = socksCL.Close() })
			socksSrv := buildSOCKS5Server(plan)
			go func() { _ = socksSrv.Serve(socksCL) }()
		}

		go recvFDLoop(sockParent, httpCL, socksCL)
		res.push(func() { _ = proxySrv.Close() })
	}

	// Close socketpair parent end when not needed for proxy fd-passing.
	if !plan.ProxyEnabled {
		_ = sockParent.Close()
	}

	// Forward signals to the child with escalation.
	stopFwd := forwardSignals(sigCh, cmd.Process, hupKillTimeout)

	// Wait for the child to exit.
	waitErr := cmd.Wait()
	stopFwd()
	signal.Stop(sigCh)
	close(sigCh)
	res.closeAll()

	return exitCode(waitErr)
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
func recvFDLoop(sock *os.File, httpCL, socksCL *proxy.ConnListener) {
	for {
		fd, tag, err := RecvFD(sock)
		if err != nil {
			_ = httpCL.Close()
			if socksCL != nil {
				_ = socksCL.Close()
			}
			return
		}
		f := os.NewFile(uintptr(fd), "proxy-conn")
		conn, fileErr := net.FileConn(f)
		_ = f.Close()
		if fileErr != nil {
			continue
		}
		var cl *proxy.ConnListener
		switch tag {
		case FDTagSOCKS5:
			cl = socksCL
		default:
			cl = httpCL
		}
		if cl == nil || cl.Enqueue(conn) != nil {
			_ = conn.Close()
		}
	}
}

// startLandlockOnly applies FS enforcement and exec's the target command
// directly. Used when user namespaces are unavailable. When plan.NoUserNS
// is true, resolveCapabilities sets UsePivotRoot=false and UseLandlock=true,
// so enforceFS naturally applies only Landlock.
func startLandlockOnly(plan *SandboxPlan) (int, error) {
	cfg := plan.childConfig()
	if err := enforceFS(&cfg, plan.Logger); err != nil {
		return -1, err
	}
	if err := enforceSeccomp(cfg.AllowUnixSockets, plan.Logger); err != nil {
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
