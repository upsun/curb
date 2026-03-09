package config

import "strings"

// DefaultHiddenPaths are sensitive dotfile directories hidden from the child process.
var DefaultHiddenPaths = []string{
	"~/.ssh",
	"~/.gnupg",
	"~/.aws",
	"~/.config/gcloud",
	"~/.docker",
}

// DefaultROPaths are system directories made available read-only.
var DefaultROPaths = []string{
	"/usr",
	"/lib",
	"/lib64",
	"/bin",
	"/sbin",
	"/etc",
	"/opt",
}

// SafePassthroughVars are environment variables always passed to the child process.
var SafePassthroughVars = []string{
	"TERM",
	"COLORTERM",
	"LANG",
	"LC_ALL",
	"LC_CTYPE",
	"TZ",
	"USER",
	"LOGNAME",
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

// DefaultPath is the default PATH value for sandboxed processes.
var DefaultPath = strings.Join(SystemExecPaths, ":")

// ForcedEnvVars returns the environment variables that are always set in the sandbox.
// HOME defaults to tmpDir unless homePath overrides it. TMPDIR is always tmpDir.
func ForcedEnvVars(tmpDir, homePath string) map[string]string {
	home := homePath
	if home == "" {
		home = tmpDir
	}
	return map[string]string{
		"HOME":   home,
		"TMPDIR": tmpDir,
		"PATH":   DefaultPath,
		"SHELL":  "/bin/sh",
	}
}

// ExpandTildes replaces a leading ~/ in each path with the given home directory.
func ExpandTildes(paths []string, home string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		if strings.HasPrefix(p, "~/") {
			out[i] = home + p[1:]
		} else {
			out[i] = p
		}
	}
	return out
}
