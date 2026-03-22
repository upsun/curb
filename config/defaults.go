package config

import (
	"path/filepath"
	"slices"
	"strings"
)

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
// TMPDIR is always tmpDir. IS_SANDBOX=1 signals to child processes that they
// are running inside a sandbox. HOME is not included here; it is resolved
// separately via resolveSandboxHome (passthrough > explicit set > tmpDir fallback)
// to allow --env HOME passthrough to take effect.
func DefaultEnvVars(tmpDir string) map[string]string {
	return map[string]string{
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
