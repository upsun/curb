package sandbox


// Capabilities holds the results of probing system capabilities.
type Capabilities struct {
	UserNS             error  // nil = ok, non-nil = fatal.
	MountNS            error  // nil = ok, non-nil = Landlock-only (no sub-path denials).
	NetNS              error  // nil = ok, non-nil = fatal if --allow-domains used.
	PidNS              error  // nil = ok, non-nil = degraded (no PID isolation).
	LandlockABI        int    // 0 = unavailable, 1-5 = version.
	Seccomp            bool   // true = seccomp-bpf filter will be applied.
	KernelInfo         string // e.g., "6.8.0-100-generic".
	Seatbelt           error  // nil = ok (macOS only), non-nil = sandbox-exec unavailable.
	OSVersion          string // macOS: e.g. "15.3.1"; empty on other platforms.
	AppArmorRestricted bool   // true = AppArmor is restricting unprivileged user namespaces (Linux only).
}

// apparmorSetupHint is appended to error messages when AppArmor is restricting user namespaces.
const apparmorSetupHint = "AppArmor is restricting unprivileged user namespaces. Run: sudo curb apparmor install"

// userNSErrMessage returns an error message for user namespace errors.
func userNSErrMessage() string {
	return `User namespaces are required but are not available.`
}

// netNSErrMessage returns an error message for network namespace errors.
func netNSErrMessage() string {
	return `Network namespaces are required for --domains but are not available.`
}

