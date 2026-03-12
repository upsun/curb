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
	caps.PidNS = probeNS(syscall.CLONE_NEWUSER|syscall.CLONE_NEWPID, "PID namespace")
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

// probeTUN checks whether /dev/net/tun is accessible and TAP creation works
// inside a user+net namespace. The full probe spawns a child that attempts
// TUNSETIFF, which catches AppArmor capability denials.
func probeTUN() error {
	f, err := os.Open("/dev/net/tun")
	if err != nil {
		return fmt.Errorf("%w: %w", errTUNDevice, err)
	}
	_ = f.Close()

	// Test TUNSETIFF inside a user+net namespace.
	self, err := os.Executable()
	if err != nil {
		return nil // Can't probe further; will fail at runtime.
	}
	cmd := exec.Command(self)
	cmd.Env = []string{TUNProbeEnvKey + "=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
	}
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = runErr.Error()
		}
		return fmt.Errorf("%w: %s", errTUNIoctl, msg)
	}
	return nil
}

// TUNProbeEnvKey is the environment variable that triggers the TUN probe child.
const TUNProbeEnvKey = "_CURB_TUN_PROBE"

// RunTUNProbe is the entry point for the TUN probe child process.
// It attempts to create and immediately destroy a TAP device.
func RunTUNProbe() {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open /dev/net/tun: %v", err)
		os.Exit(1)
	}
	ifr, err := unix.NewIfreq("probe0")
	if err != nil {
		_ = unix.Close(fd)
		fmt.Fprintf(os.Stderr, "ifreq: %v", err)
		os.Exit(1)
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		fmt.Fprintf(os.Stderr, "TUNSETIFF: %v", err)
		os.Exit(1)
	}
	_ = unix.Close(fd)
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
