//go:build darwin

package config

// DefaultROPaths are system directories made available read-only on macOS.
// macOS uses /private/etc for configuration and /Library for system-wide resources.
var DefaultROPaths = []string{
	"/usr",
	"/bin",
	"/sbin",
	"/opt",
	"/Library",
	"/System",
	"/private/etc/ssl",
	"/private/etc/pki",
}

// DefaultROFiles are individual files made available read-only on macOS.
var DefaultROFiles = []string{
	"/dev/urandom",
	"/dev/random",
	"/private/etc/resolv.conf",
	"/private/etc/hosts",
	"/private/etc/localtime",
	"/private/etc/passwd",
	"/private/etc/group",
}

// DefaultRWPaths are directories that need write access by default on macOS.
// PTY access is handled by the Seatbelt pseudo-tty rule, not path rules.
var DefaultRWPaths []string

// DefaultRWFiles are device nodes that need write access on macOS.
var DefaultRWFiles = []string{
	"/dev/null",
	"/dev/zero",
}

// SystemExecPaths are directories from which executables are allowed by default on macOS.
// Empty: only the invoked command and profile/flag additions are executable.
// Use the "shell" profile or --exec to allow system binaries.
var SystemExecPaths []string
