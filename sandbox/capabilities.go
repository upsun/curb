package sandbox

import "errors"

// Sentinel errors for TUN probe failures.
var (
	errTUNDevice = errors.New("tun device unavailable")
	errTUNIoctl  = errors.New("TAP ioctl failed in namespace")
)

// Capabilities holds the results of probing system capabilities.
type Capabilities struct {
	UserNS      error  // nil = ok, non-nil = fatal.
	MountNS     error  // nil = ok, non-nil = fatal if --hide used.
	NetNS       error  // nil = ok, non-nil = fatal if --allow-domains used.
	TUN         error  // nil = ok, non-nil = fatal if --allow-domains used.
	LandlockABI int    // 0 = unavailable, 1-5 = version.
	KernelInfo  string // e.g., "6.8.0-100-generic".
}

// userNSErrMessage returns an error message for user namespace errors.
func userNSErrMessage() string {
	return `User namespaces are required but are not available.`
}

// netNSErrMessage returns an error message for network namespace errors.
func netNSErrMessage() string {
	return `Network namespaces are required for --allow-domains/--allow-localhost but are not available.`
}

// tunDeviceErrMessage returns an error message when /dev/net/tun does not exist.
func tunDeviceErrMessage() string {
	return `/dev/net/tun is required for --allow-domains/--allow-localhost but is not available.`
}

// tunIoctlErrMessage returns an error message when /dev/net/tun exists but
// TUNSETIFF fails (e.g. AppArmor blocking CAP_NET_ADMIN in user namespaces).
func tunIoctlErrMessage() string {
	return `/dev/net/tun exists but TAP creation failed inside a user+network namespace.`
}

// landlockWarnMessage returns a warning for missing Landlock support.
func landlockWarnMessage() string {
	return `Landlock is not available (requires kernel 5.13+).
  Filesystem restrictions will use mount namespace and seccomp-bpf only (weaker).`
}
