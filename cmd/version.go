package cmd

import (
	"runtime/debug"
	"strings"
)

// versionInfo returns the version string derived from Go build info.
// It uses the module version when available (tagged releases via go install),
// falling back to the Go pseudo-version with VCS details.
func versionInfo() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "(unknown)"
	}

	version := bi.Main.Version
	if version == "" || version == "(devel)" {
		version = "dev"
	}

	var revision string
	var modified bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}

	// For dev/pseudo-versions, use the pseudo-version directly
	// (it already encodes the commit hash and timestamp).
	if strings.HasPrefix(version, "v0.0.0-") || version == "dev" {
		if modified && !strings.HasSuffix(version, "+dirty") {
			version += "+dirty"
		}
		return version
	}

	// For tagged releases, append short commit hash and dirty state.
	if revision != "" {
		if len(revision) > 12 {
			revision = revision[:12]
		}
		version += " (" + revision
		if modified {
			version += ", dirty"
		}
		version += ")"
	}
	return version
}
