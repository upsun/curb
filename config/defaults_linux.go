//go:build linux

package config

// DefaultROPaths are system directories and pseudo-filesystems made available read-only.
var DefaultROPaths = []string{
	"/usr",
	"/lib",
	"/lib64",
	"/bin",
	"/sbin",
	"/opt",
	// /proc is safe to expose fully: the user namespace blocks ptrace-guarded
	// access (e.g. /proc/[pid]/environ) for processes outside the namespace.
	"/proc",
	// Granular /etc entries instead of the whole directory.
	"/etc/ssl",
	"/etc/ca-certificates",
	"/etc/pki",
	"/etc/ld.so.conf.d",
	"/etc/alternatives",
}

// DefaultROFiles are individual files made available read-only.
// Separated from DefaultROPaths because Landlock requires different access
// rights for files vs directories.
var DefaultROFiles = []string{
	"/dev/urandom",
	"/dev/random",
	"/etc/ld.so.cache",
	"/etc/ld.so.conf",
	"/etc/nsswitch.conf",
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/localtime",
	"/etc/timezone",
	"/etc/passwd",
	"/etc/group",
	"/etc/os-release",
	"/etc/gai.conf",
	"/etc/bash.bashrc",
}

// DefaultRWPaths are directories that need write access by default.
var DefaultRWPaths = []string{
	// Interactive programs need read-write access to their terminal device.
	"/dev/pts",
}

// DefaultRWFiles are device nodes that need write access (e.g. /dev/null as an output target).
var DefaultRWFiles = []string{
	"/dev/null",
	"/dev/zero",
	"/dev/ptmx",
}

// SystemExecPaths are directories from which executables are allowed by default.
// Empty: only the invoked command, dynamic linker, and profile/flag additions
// are executable. Use the "shell" profile or --exec to allow system binaries.
var SystemExecPaths []string
