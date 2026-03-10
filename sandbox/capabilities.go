package sandbox

// Capabilities holds the results of probing system capabilities.
type Capabilities struct {
	UserNS      error  // nil = ok, non-nil = fatal.
	MountNS     error  // nil = ok, non-nil = fatal if --hide used.
	NetNS       error  // nil = ok, non-nil = fatal if --allow-domains used.
	TUN         error  // nil = ok, non-nil = fatal if --allow-domains used.
	LandlockABI int    // 0 = unavailable, 1-5 = version.
	KernelInfo  string // e.g., "6.8.0-100-generic".
}

// userNSFixMessage returns an actionable fix message for user namespace errors.
func userNSFixMessage() string {
	return `User namespaces are required but not available.

  To fix (temporarily):
    sudo sysctl -w kernel.unprivileged_userns_clone=1

  To fix (permanently):
    echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/99-userns.conf
    sudo sysctl --system`
}

// netNSFixMessage returns an actionable fix message for network namespace errors.
func netNSFixMessage() string {
	return `Network namespaces are required for --allow-domains/--allow-localhost but not available.

  To fix (temporarily):
    sudo sysctl -w kernel.unprivileged_userns_clone=1

  Remove --allow-domains/--allow-localhost to run without network filtering.`
}

// tunFixMessage returns an actionable fix message for TUN device errors.
func tunFixMessage() string {
	return `/dev/net/tun is required for --allow-domains/--allow-localhost but not available.

  To fix (device missing):
    sudo mkdir -p /dev/net
    sudo mknod /dev/net/tun c 10 200
    sudo chmod 0666 /dev/net/tun

  If AppArmor blocks TUN/TAP creation (TUNSETIFF: operation not permitted):
    1. Comment out 'audit deny capability,' in /etc/apparmor.d/unprivileged_userns
    2. Add rules to /etc/apparmor.d/local/unprivileged_userns:
         capability net_admin,
         owner file rw dev/pts/[0-9]*,
       The devpts rule fixes fstat errors on terminal devices (disconnected paths).
       For full DNS support, also add: capability sys_admin,
    3. sudo apparmor_parser -r /etc/apparmor.d/unprivileged_userns

  Remove --allow-domains/--allow-localhost to run without network filtering.`
}

// landlockWarnMessage returns a warning for missing Landlock support.
func landlockWarnMessage() string {
	return `Landlock is not available (requires kernel 5.13+).
  Filesystem restrictions will use mount namespace and seccomp-bpf only (weaker).`
}
