//go:build linux

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/upsun/curb/policy"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// ChildInit is the entry point for the re-exec'd child process inside new namespaces.
// It reads the sandbox config from fd 3, applies sandbox layers,
// and execs the target command. It never returns on success.
func ChildInit() {
	if err := childInit(); err != nil {
		fmt.Fprintf(os.Stderr, "curb: error: child init: %v\n", err)
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

	// Network setup: create TAP and send fd to parent before Landlock
	// (Landlock would block /dev/net/tun access).
	if cfg.NetEnabled {
		if err := setupChildNetwork(sockFile, cfg.Quiet); err != nil {
			_ = sockFile.Close()
			return fmt.Errorf("network setup: %w", err)
		}
	}
	_ = sockFile.Close()

	// Filesystem enforcement: mounts first, then Landlock.
	// Landlock would block mount syscalls if enforced first.
	if !cfg.NoFSRestrict {
		mountsOK := prepareMountNS(cfg.Quiet)
		if mountsOK {
			if err := hidePaths(cfg.HiddenPaths); err != nil {
				return fmt.Errorf("hiding paths: %w", err)
			}
			if cfg.GitHooksPath != "" {
				if err := protectHooksDir(cfg.GitHooksPath); err != nil {
					return fmt.Errorf("protecting hooks dir: %w", err)
				}
			}
		}
		rules := policy.BuildLandlockRules(cfg.ROPaths, cfg.RWPaths, cfg.ExecPaths)
		if len(rules) > 0 {
			if err := policy.EnforceLandlock(rules); err != nil {
				return fmt.Errorf("enforcing landlock: %w", err)
			}
		}
	}

	if len(cfg.Command) == 0 {
		return fmt.Errorf("no command specified")
	}

	exe, err := findExecutable(cfg.Command[0], cfg.Env)
	if err != nil {
		return err
	}

	return syscall.Exec(exe, cfg.Command, cfg.Env)
}

// childWarn prints a warning to stderr from the child process.
// Suppressed if quiet is true. Uses color if stderr is a terminal.
func childWarn(quiet bool, format string, args ...any) {
	if quiet {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if term.IsTerminal(int(os.Stderr.Fd())) && os.Getenv("NO_COLOR") == "" {
		fmt.Fprintf(os.Stderr, "\033[33mcurb: warning:\033[0m %s\n", msg)
	} else {
		fmt.Fprintf(os.Stderr, "curb: warning: %s\n", msg)
	}
}

// prepareMountNS makes mount propagation slave so overmounts don't propagate to host.
// Returns false if mount operations are not available (e.g. AppArmor restrictions).
func prepareMountNS(quiet bool) bool {
	err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_SLAVE, "")
	if err != nil {
		childWarn(quiet, "Dotfile hiding and hooks protection unavailable (mount namespace restricted).")
		return false
	}
	return true
}

// hidePaths overmounts each path with an empty tmpfs, making the original content invisible.
// Non-existent paths are silently skipped.
func hidePaths(paths []string) error {
	for _, p := range paths {
		if err := syscall.Mount("tmpfs", p, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=0"); err != nil {
			if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			return fmt.Errorf("overmounting %s: %w", p, err)
		}
	}
	return nil
}

// protectHooksDir bind-mounts a Git hooks directory as read-only.
func protectHooksDir(hooksPath string) error {
	// Bind-mount the directory on itself.
	if err := syscall.Mount(hooksPath, hooksPath, "", syscall.MS_BIND, ""); err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR) {
			return nil
		}
		return fmt.Errorf("bind mount %s: %w", hooksPath, err)
	}
	// Remount as read-only.
	if err := syscall.Mount("", hooksPath, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("remount ro %s: %w", hooksPath, err)
	}
	return nil
}


// setupChildNetwork creates a TAP device, configures interfaces, sends the TAP
// fd to the parent, and waits for a ready signal before continuing.
func setupChildNetwork(sockFile *os.File, quiet bool) error {
	tapFD, err := createTAP()
	if err != nil {
		return err
	}
	ifindex, err := configureInterfaces()
	if err != nil {
		_ = unix.Close(tapFD)
		return err
	}
	if err := routeLoopback(ifindex); err != nil {
		childWarn(quiet, "DNS and localhost services may not work (loopback routing failed).")
	}
	if err := SendFD(sockFile, tapFD); err != nil {
		_ = unix.Close(tapFD)
		return fmt.Errorf("sending TAP fd: %w", err)
	}
	_ = unix.Close(tapFD)

	// Wait for parent to signal that the netstack is ready.
	readyBuf := make([]byte, 1)
	if _, err := sockFile.Read(readyBuf); err != nil {
		return fmt.Errorf("waiting for netstack ready: %w", err)
	}
	return nil
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
