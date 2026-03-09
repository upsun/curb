//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// ProbeAll runs all capability probes and returns the results.
func ProbeAll() *Capabilities {
	caps := &Capabilities{}
	caps.KernelInfo = probeKernel()
	caps.UserNS = probeNS(syscall.CLONE_NEWUSER, "user namespace")
	caps.MountNS = probeNS(syscall.CLONE_NEWUSER|syscall.CLONE_NEWNS, "mount namespace")
	caps.NetNS = probeNS(syscall.CLONE_NEWUSER|syscall.CLONE_NEWNET, "network namespace")
	caps.TUN = probeTUN()
	caps.LandlockABI = probeLandlock()
	return caps
}

func probeKernel() string {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "unknown"
	}
	return strings.TrimRight(string(uname.Release[:]), "\x00")
}

// probeNS tests namespace creation by spawning a child with the given clone flags.
func probeNS(flags uintptr, name string) error {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: flags,
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s creation failed: %w", name, err)
	}
	return nil
}

func probeTUN() error {
	f, err := os.Open("/dev/net/tun")
	if err != nil {
		return fmt.Errorf("/dev/net/tun unavailable: %w", err)
	}
	_ = f.Close()
	return nil
}

func probeLandlock() int {
	// LandlockCreateRuleset with LANDLOCK_CREATE_RULESET_VERSION returns the ABI version.
	r, _, errno := syscall.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0, // attr = NULL
		0, // size = 0
		1, // flags = LANDLOCK_CREATE_RULESET_VERSION
	)
	if errno != 0 {
		return 0
	}
	return int(r)
}
