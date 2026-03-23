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

// MountProbeEnvKey is the environment variable that triggers the mount probe child.
const MountProbeEnvKey = "_CURB_MOUNT_PROBE"

// RunMountProbe is the entry point for the mount probe child process.
// It tests MS_SLAVE propagation, tmpfs mount, bind-mount, and pivot_root
// inside a user+mount namespace. The bind-mount tests catch AppArmor
// policies and Docker overlay filesystems that reject certain bind sources.
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

	// Test bind-mount with /usr (exists on all Linux systems).
	bindDst := dir + "/bind"
	if err := os.Mkdir(bindDst, 0o755); err != nil {
		_ = syscall.Unmount(dir, 0)
		fmt.Fprintf(os.Stderr, "mkdir bind target: %v", err)
		os.Exit(1)
	}
	if err := syscall.Mount("/usr", bindDst, "", syscall.MS_BIND, ""); err != nil {
		_ = syscall.Unmount(dir, 0)
		fmt.Fprintf(os.Stderr, "bind mount /usr: %v", err)
		os.Exit(1)
	}
	_ = syscall.Unmount(bindDst, 0)

	// Test bind-mount with /etc. Docker overlay filesystems may reject this
	// with EINVAL even when /usr succeeds, because /etc contains sub-mounts
	// (hostname, hosts, resolv.conf) injected by the container runtime.
	if err := syscall.Mount("/etc", bindDst, "", syscall.MS_BIND, ""); err != nil {
		_ = syscall.Unmount(dir, 0)
		fmt.Fprintf(os.Stderr, "bind mount /etc: %v", err)
		os.Exit(1)
	}
	_ = syscall.Unmount(bindDst, 0)

	// Test pivot_root into the tmpfs. After pivot_root the root filesystem
	// is the tiny tmpfs, so exit immediately via syscall to avoid Go runtime
	// issues (e.g. /proc unavailable).
	putOld := dir + "/.old"
	if err := os.Mkdir(putOld, 0o755); err != nil {
		_ = syscall.Unmount(dir, 0)
		fmt.Fprintf(os.Stderr, "mkdir pivot old: %v", err)
		os.Exit(1)
	}
	if err := syscall.PivotRoot(dir, putOld); err != nil {
		_ = syscall.Unmount(dir, 0)
		fmt.Fprintf(os.Stderr, "pivot_root: %v", err)
		os.Exit(1)
	}
	syscall.Exit(0)
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
