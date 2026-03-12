package config

import (
	"path/filepath"
	"slices"
	"strings"
)

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

// SafePassthroughVars are environment variables always passed to the child process.
var SafePassthroughVars = []string{
	"PATH",
	"TERM",
	"COLORTERM",
	"NO_COLOR",
	"LANG",
	"LC_ALL",
	"LC_CTYPE",
	"TZ",
	"USER",
	"LOGNAME",
	"SHELL",
}

// SystemExecPaths are directories from which executables are allowed by default.
// Includes lib directories because the kernel checks Landlock EXECUTE when
// loading the ELF interpreter (dynamic linker) via open_exec().
var SystemExecPaths = []string{
	"/usr/bin",
	"/bin",
	"/usr/local/bin",
	"/usr/sbin",
	"/sbin",
	"/lib",
	"/lib64",
}

// ParseExclusions separates args into adds, specific removes, and removeAll.
// A "!" prefix marks a removal. "!*" removes all defaults. "\!" escapes a
// literal "!" at the start of a path.
func ParseExclusions(args []string) (adds, removes []string, removeAll bool) {
	for _, a := range args {
		switch {
		case a == "!*":
			removeAll = true
		case strings.HasPrefix(a, "!"):
			removes = append(removes, a[1:])
		case strings.HasPrefix(a, `\!`):
			adds = append(adds, "!"+a[2:])
		default:
			adds = append(adds, a)
		}
	}
	return
}

// ApplyExclusions merges user args with defaults. Args prefixed with ! remove
// matching defaults. !* removes all defaults. Other args are appended.
func ApplyExclusions(defaults, args []string) []string {
	adds, removes, removeAll := ParseExclusions(args)
	if removeAll {
		return adds
	}
	if len(removes) == 0 {
		return append(slices.Clone(defaults), adds...)
	}
	removeSet := make(map[string]bool, len(removes))
	for _, r := range removes {
		removeSet[r] = true
	}
	var result []string
	for _, d := range defaults {
		if !removeSet[d] {
			result = append(result, d)
		}
	}
	return append(result, adds...)
}

// DefaultEnvVars returns the default environment variables set in the sandbox.
// HOME defaults to tmpDir unless homePath overrides it. TMPDIR is always tmpDir.
// IS_SANDBOX=1 signals to child processes that they are running inside a
// sandbox (e.g. to allow root-like operations that are safe in a user
// namespace). Callers on platforms without real sandboxing should remove it.
func DefaultEnvVars(tmpDir, homePath string) map[string]string {
	home := homePath
	if home == "" {
		home = tmpDir
	}
	return map[string]string{
		"HOME":       home,
		"TMPDIR":     tmpDir,
		"IS_SANDBOX": "1",
	}
}

// DefaultPS1 returns a PS1 prompt with a (curb) prefix, using the correct
// escape syntax for the given shell. Set noColor to suppress ANSI escapes.
func DefaultPS1(command string, noColor bool) string {
	shell := filepath.Base(command)
	switch shell {
	case "zsh":
		if noColor {
			return "(curb) %n:%~%# "
		}
		return "%F{cyan}(curb)%f %n:%~%# "
	case "bash":
		if noColor {
			return `(curb) \u:\w\$ `
		}
		return `\[\033[36m\](curb)\[\033[0m\] \u:\w\$ `
	default:
		return "(curb) $ "
	}
}

// ExpandGlobs expands glob patterns in the path list. Paths without glob
// metacharacters are passed through unchanged. Patterns that match nothing
// (or have invalid syntax) are silently dropped.
func ExpandGlobs(paths []string) []string {
	var expanded []string
	for _, p := range paths {
		if !hasGlobMeta(p) {
			expanded = append(expanded, p)
			continue
		}
		matches, err := filepath.Glob(p)
		if err != nil || len(matches) == 0 {
			continue
		}
		expanded = append(expanded, matches...)
	}
	return expanded
}

// hasGlobMeta reports whether path contains glob metacharacters.
func hasGlobMeta(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

// ExpandTildes replaces a leading ~ or ~/ in each path with the given home directory.
func ExpandTildes(paths []string, home string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		if p == "~" {
			out[i] = home
		} else if strings.HasPrefix(p, "~/") {
			out[i] = home + p[1:]
		} else {
			out[i] = p
		}
	}
	return out
}
