//go:build unix

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
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

// hupKillTimeout is the delay after SIGHUP before force-killing the child.
// Terminal is gone after HUP so the user cannot send further signals.
const hupKillTimeout = 3 * time.Second

// termSignal extracts the syscall.Signal if sig is SIGINT, SIGTERM, or SIGHUP.
// Returns 0 (not a termination signal) otherwise.
func termSignal(sig os.Signal) syscall.Signal {
	s, ok := sig.(syscall.Signal)
	if !ok {
		return 0
	}
	if s == syscall.SIGINT || s == syscall.SIGTERM || s == syscall.SIGHUP {
		return s
	}
	return 0
}

// forwardSignals relays signals from sigCh to proc. On a second termination
// signal (SIGINT, SIGTERM, SIGHUP) it force-kills the child. If SIGHUP is
// the first termination signal, a kill timer is also started (the terminal is
// gone so the user cannot send a second signal manually).
// Returns a stop function that cancels the HUP timer; call it after Wait().
func forwardSignals(sigCh <-chan os.Signal, proc *os.Process, hupTimeout time.Duration) (stop func()) {
	var (
		mu       sync.Mutex
		termSent bool
		timer    *time.Timer
		killed   sync.Once
	)
	kill := func() {
		killed.Do(func() {
			if err := proc.Kill(); err == nil {
				fmt.Fprintf(os.Stderr, "curb: killing child (signal escalation)\n")
			}
		})
	}
	go func() {
		for sig := range sigCh {
			if ts := termSignal(sig); ts != 0 {
				mu.Lock()
				if termSent {
					mu.Unlock()
					kill()
					continue
				}
				termSent = true
				if ts == syscall.SIGHUP && timer == nil {
					timer = time.AfterFunc(hupTimeout, kill)
				}
				mu.Unlock()
			}
			_ = proc.Signal(sig)
		}
	}()
	return func() {
		mu.Lock()
		defer mu.Unlock()
		if timer != nil {
			timer.Stop()
		}
	}
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
