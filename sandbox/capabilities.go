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
	MountNS     error  // nil = ok, non-nil = degraded (no sub-path denials).
	NetNS       error  // nil = ok, non-nil = fatal if --allow-domains used.
	TUN         error  // nil = ok, non-nil = fatal if --allow-domains used.
	PidNS       error  // nil = ok, non-nil = degraded (no PID isolation).
	LandlockABI int    // 0 = unavailable, 1-5 = version.
	KernelInfo  string // e.g., "6.8.0-100-generic".
}

// userNSErrMessage returns an error message for user namespace errors.
func userNSErrMessage() string {
	return `User namespaces are required but are not available.`
}

// netNSErrMessage returns an error message for network namespace errors.
func netNSErrMessage() string {
	return `Network namespaces are required for --domains but are not available.`
}

// tunDeviceErrMessage returns an error message when /dev/net/tun does not exist.
func tunDeviceErrMessage() string {
	return `/dev/net/tun is required for --domains but is not available.`
}

// tunIoctlErrMessage returns an error message when /dev/net/tun exists but
// TUNSETIFF fails (e.g. AppArmor blocking CAP_NET_ADMIN in user namespaces).
func tunIoctlErrMessage() string {
	return `/dev/net/tun exists but TAP creation failed inside a user+network namespace.`
}

