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
	caps.UserNS = probeUserNS()
	caps.MountNS = probeMountNS()
	caps.NetNS = probeNetNS()
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

func probeUserNS() error {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("user namespace creation failed: %w", err)
	}
	return nil
}

func probeMountNS() error {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mount namespace creation failed: %w", err)
	}
	return nil
}

func probeNetNS() error {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("network namespace creation failed: %w", err)
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
