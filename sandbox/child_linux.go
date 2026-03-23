//go:build linux

package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/upsun/curb/clog"
	"github.com/upsun/curb/policy"
)

// ChildInit is the entry point for the re-exec'd child process inside new namespaces.
// It reads the sandbox config from fd 3, applies sandbox layers,
// and execs the target command. It never returns on success.
func ChildInit() {
	if err := childInit(); err != nil {
		clog.Errorf("%v", err)
		os.Exit(ExitSetupFailure)
	}
}

func childInit() error {
	configFile := os.NewFile(childConfigFD, "config-pipe")
	sockFile := os.NewFile(childSocketFD, "socketpair")

	var cfg ChildConfig
	if err := json.NewDecoder(configFile).Decode(&cfg); err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	_ = configFile.Close()

	// Proxy mode: the child runs the accept loop and relays fds to the parent.
	// This must happen before FS enforcement (needs lo interface up).
	if cfg.ProxyEnabled {
		// Close sockFile after proxyRelayInit returns (it stays open for fd-passing).
		return proxyRelayInit(sockFile, &cfg)
	}
	_ = sockFile.Close()

	// Filesystem enforcement: pivot_root first, then Landlock.
	if err := enforceFS(&cfg); err != nil {
		return err
	}

	// Seccomp: block AF_UNIX socket creation (abstract socket escape prevention).
	if err := enforceSeccomp(cfg.AllowUnixSockets); err != nil {
		return err
	}

	if len(cfg.Command) == 0 {
		return fmt.Errorf("no command specified")
	}

	exe, err := findExecutable(cfg.Command[0], cfg.Env)
	if err != nil {
		return err
	}

	if cfg.PidNS {
		return pidNSInit(exe, cfg.Command, cfg.Env)
	}
	return syscall.Exec(exe, cfg.Command, cfg.Env)
}

// pidNSInit acts as PID 1 inside the PID namespace: it forks the target
// command, forwards signals to it, and reaps orphaned children.
func pidNSInit(exe string, argv, env []string) error {
	return initLoop(exe, argv, env, nil)
}

// initLoop forks+execs the target command, forwards signals, and reaps
// children. cleanup (if non-nil) is called after the target exits, before
// os.Exit. Used by both pidNSInit and proxyRelayInit.
func initLoop(exe string, argv, env []string, cleanup func()) error {
	pid, err := syscall.ForkExec(exe, argv, &syscall.ProcAttr{
		Env:   env,
		Files: []uintptr{0, 1, 2},
		Sys:   &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL},
	})
	if err != nil {
		return fmt.Errorf("fork+exec %s: %w", exe, err)
	}

	// Forward all catchable signals (except SIGCHLD) to the target.
	sigs := catchableSignals()
	filtered := make([]os.Signal, 0, len(sigs))
	for _, s := range sigs {
		if s != os.Signal(syscall.SIGCHLD) {
			filtered = append(filtered, s)
		}
	}
	sigCh := make(chan os.Signal, 32)
	signal.Notify(sigCh, filtered...)
	proc, _ := os.FindProcess(pid)
	stopFwd := forwardSignals(sigCh, proc, hupKillTimeout)

	// Reap loop: wait for the target to exit, silently reaping orphans.
	var targetStatus syscall.WaitStatus
	targetFound := false
	for {
		var ws syscall.WaitStatus
		wpid, waitErr := syscall.Wait4(-1, &ws, 0, nil)
		if waitErr != nil {
			break // ECHILD: no more children.
		}
		if wpid == pid {
			targetStatus = ws
			targetFound = true
			break
		}
	}
	// Drain remaining zombies.
	for {
		var ws syscall.WaitStatus
		wpid, waitErr := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if waitErr != nil || wpid <= 0 {
			break
		}
	}

	stopFwd()
	signal.Stop(sigCh)
	close(sigCh)

	if cleanup != nil {
		cleanup()
	}

	if !targetFound {
		os.Exit(1)
	}
	if targetStatus.Signaled() {
		signal.Reset(targetStatus.Signal())
		_ = syscall.Kill(syscall.Getpid(), targetStatus.Signal())
		os.Exit(128 + int(targetStatus.Signal()))
	}
	os.Exit(targetStatus.ExitStatus())
	return nil // Unreachable.
}

type landlockEnforcer struct{ paths policy.LandlockPaths }

func (e *landlockEnforcer) Enforce() error {
	rules := policy.BuildLandlockRules(e.paths)
	if len(rules) == 0 {
		return nil
	}
	if err := policy.EnforceLandlock(rules); err != nil {
		return fmt.Errorf("enforcing landlock: %w", err)
	}
	return nil
}

// fsEnforcers returns the ordered list of filesystem enforcers for the config.
// pivot_root is applied first (if available), then Landlock for defense-in-depth.
func fsEnforcers(cfg *ChildConfig) []FSEnforcer {
	if cfg.NoFSRestrict {
		return nil
	}
	var enforcers []FSEnforcer
	if cfg.UsePivotRoot {
		enforcers = append(enforcers, &pivotRootEnforcer{cfg: cfg})
	}
	if cfg.UseLandlock {
		enforcers = append(enforcers, &landlockEnforcer{paths: cfg.LandlockPaths()})
	}
	return enforcers
}

// enforceFS applies filesystem enforcement (pivot_root + Landlock) from the
// child config. Called from both childInit and proxyRelayInit.
func enforceFS(cfg *ChildConfig) error {
	for _, e := range fsEnforcers(cfg) {
		if err := e.Enforce(); err != nil {
			return err
		}
	}
	return nil
}

// childWarn prints a warning to stderr from the child process.
// Suppressed if quiet is true.
func childWarn(quiet bool, format string, args ...any) {
	if quiet {
		return
	}
	clog.Warnf(format, args...)
}

// prepareMountNS makes mount propagation slave so overmounts don't propagate to host.
func prepareMountNS() error {
	return syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_SLAVE, "")
}

// findExecutable resolves a command name to an absolute path using the PATH from env.
func findExecutable(name string, env []string) (string, error) {
	if filepath.IsAbs(name) {
		info, err := os.Stat(name)
		if err != nil {
			return "", fmt.Errorf("executable %q: %w", name, err)
		}
		if info.IsDir() || info.Mode()&0111 == 0 {
			return "", fmt.Errorf("executable %q: not an executable file", name)
		}
		return name, nil
	}
	var pathEnv string
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			pathEnv = e[5:]
			break
		}
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() && info.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("executable %q not found in PATH", name)
}
