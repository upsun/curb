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
	caps.AppArmorRestricted = isAppArmorRestrictingUserns()
	caps.UserNS = probeNS(syscall.CLONE_NEWUSER, "user namespace")
	caps.MountNS = probeMountOps(caps.AppArmorRestricted)
	caps.NetNS = probeNS(syscall.CLONE_NEWUSER|syscall.CLONE_NEWNET, "network namespace")
	caps.PidNS = probeNS(syscall.CLONE_NEWUSER|syscall.CLONE_NEWPID, "PID namespace")
	caps.LandlockABI = probeLandlock()
	caps.Seccomp = true // seccomp-bpf available since kernel 3.5.
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
func (c *Capabilities) probeTUN() error {
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

// MountProbeEnvKey is the environment variable that triggers the mount probe child.
const MountProbeEnvKey = "_CURB_MOUNT_PROBE"

// RunMountProbe is the entry point for the mount probe child process.
// It tests MS_SLAVE propagation, tmpfs mount, and bind-mount inside a
// user+mount namespace. The bind-mount test catches AppArmor policies that
// allow tmpfs but block bind mounts (e.g. the default unprivileged_userns
// profile on Ubuntu 24.04+).
func RunMountProbe() {
	if err := prepareMountNS(); err != nil {
		fmt.Fprintf(os.Stderr, "MS_SLAVE: %v", err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "curb-probe-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdirtemp: %v", err)
		os.Exit(1)
	}
	defer func() { _ = os.Remove(dir) }()
	if err := syscall.Mount("tmpfs", dir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size=4k"); err != nil {
		fmt.Fprintf(os.Stderr, "tmpfs mount: %v", err)
		os.Exit(1)
	}
	// Test bind-mount: pivot_root enforcement relies on binding host paths
	// into the new root. Use /usr as the source (exists on all Linux systems).
	bindDst := dir + "/bind"
	if err := os.Mkdir(bindDst, 0o755); err != nil {
		_ = syscall.Unmount(dir, 0)
		fmt.Fprintf(os.Stderr, "mkdir bind target: %v", err)
		os.Exit(1)
	}
	if err := syscall.Mount("/usr", bindDst, "", syscall.MS_BIND, ""); err != nil {
		_ = syscall.Unmount(dir, 0)
		fmt.Fprintf(os.Stderr, "bind mount: %v", err)
		os.Exit(1)
	}
	_ = syscall.Unmount(bindDst, 0)
	_ = syscall.Unmount(dir, 0)
}

// probeMountOps tests whether mount operations (MS_SLAVE, tmpfs mount, bind
// mount) work inside a user+mount namespace. This catches AppArmor policies
// that allow namespace creation but block mount syscalls.
func probeMountOps(appArmorRestricted bool) error {
	self, err := os.Executable()
	if err != nil {
		// Can't probe; fall back to basic namespace probe.
		return probeNS(syscall.CLONE_NEWUSER|syscall.CLONE_NEWNS, "mount namespace")
	}
	cmd := exec.Command(self)
	cmd.Env = []string{MountProbeEnvKey + "=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
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
		e := fmt.Errorf("mount operations failed in namespace: %s", msg)
		if appArmorRestricted {
			e = fmt.Errorf("%w; %s", e, apparmorSetupHint)
		}
		return e
	}
	return nil
}

// isAppArmorRestrictingUserns reports whether AppArmor is enabled and
// restricting capabilities in unprivileged user namespaces.
func isAppArmorRestrictingUserns() bool {
	enabled, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
	if err != nil || strings.TrimSpace(string(enabled)) != "Y" {
		return false
	}
	restrict, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	if err != nil || strings.TrimSpace(string(restrict)) != "1" {
		return false
	}
	return true
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
