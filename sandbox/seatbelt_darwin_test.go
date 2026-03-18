//go:build darwin

package sandbox

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateSBPL_DenyDefault(t *testing.T) {
	plan := &SandboxPlan{
		Caps:        &Capabilities{},
		NoFSRestrict: true,
	}
	profile := generateSBPL(plan)
	assert.Contains(t, profile, "(version 1)")
	assert.Contains(t, profile, "(deny default)")
	assert.Contains(t, profile, `(import "system.sb")`)
}

func TestGenerateSBPL_ROPaths(t *testing.T) {
	plan := &SandboxPlan{
		Caps:    &Capabilities{},
		ROPaths: []string{"/usr", "/opt"},
		ROFiles: []string{"/private/etc/hosts"},
		NoFSRestrict: true,
	}
	profile := generateSBPL(plan)
	assert.Contains(t, profile, `(subpath "/usr")`)
	assert.Contains(t, profile, `(subpath "/opt")`)
	assert.Contains(t, profile, `(literal "/private/etc/hosts")`)
}

func TestGenerateSBPL_RWPaths(t *testing.T) {
	plan := &SandboxPlan{
		Caps:    &Capabilities{},
		RWPaths: []string{"/private/tmp/curb-test"},
		RWFiles: []string{"/dev/null"},
		NoFSRestrict: true,
	}
	profile := generateSBPL(plan)
	assert.Contains(t, profile, "file-read* file-write*")
	assert.Contains(t, profile, `(subpath "/private/tmp/curb-test")`)
	assert.Contains(t, profile, `(literal "/dev/null")`)
}

func TestGenerateSBPL_DenyRules(t *testing.T) {
	plan := &SandboxPlan{
		Caps:           &Capabilities{},
		HiddenPaths:    []string{"/private/etc/passwd"},
		DenyWritePaths: []string{"/usr/local/lib"},
		DenyExecPaths:  []string{"/opt/bad"},
		NoFSRestrict:   true,
	}
	profile := generateSBPL(plan)
	assert.Contains(t, profile, `(deny file-read* file-write* (subpath "/private/etc/passwd"))`)
	assert.Contains(t, profile, `(deny file-write* (subpath "/usr/local/lib"))`)
	assert.Contains(t, profile, `(deny process-exec (subpath "/opt/bad"))`)
}

func TestGenerateSBPL_MoveProtection(t *testing.T) {
	plan := &SandboxPlan{
		Caps:        &Capabilities{},
		HiddenPaths: []string{"/private/var/secrets"},
		NoFSRestrict: true,
	}
	profile := generateSBPL(plan)
	// Ancestor directories should be protected against rename.
	assert.Contains(t, profile, `(deny file-write-unlink (literal "/private/var"))`)
	assert.Contains(t, profile, `(deny file-write-unlink (literal "/private"))`)
}

func TestGenerateSBPL_ProxyNetwork(t *testing.T) {
	plan := &SandboxPlan{
		Caps:         &Capabilities{},
		ProxyEnabled: true,
		ProxyPort:    51234,
		NoFSRestrict: true,
	}
	profile := generateSBPL(plan)
	assert.Contains(t, profile, `(allow network-outbound (remote ip "localhost:51234"))`)
	// Proxy runs in the parent; child should not need network-bind.
	assert.NotContains(t, profile, "network-bind")
	// Proxy needs TLS mach services.
	assert.Contains(t, profile, `"com.apple.SecurityServer"`)
	assert.Contains(t, profile, `"com.apple.trustd.agent"`)
}

func TestGenerateSBPL_UnrestrictedNet(t *testing.T) {
	plan := &SandboxPlan{
		Caps:            &Capabilities{},
		UnrestrictedNet: true,
		NoFSRestrict:    true,
	}
	profile := generateSBPL(plan)
	assert.Contains(t, profile, "(allow network*)")
}

func TestGenerateSBPL_IPOnly(t *testing.T) {
	plan := &SandboxPlan{
		Caps:       &Capabilities{},
		AllowedIPs: []string{"10.0.0.1"},
		NoFSRestrict: true,
	}
	profile := generateSBPL(plan)
	assert.Contains(t, profile, `(allow network-outbound (remote ip "10.0.0.1:*"))`)
}

func TestGenerateSBPL_AFUnixBlocked(t *testing.T) {
	plan := &SandboxPlan{
		Caps:         &Capabilities{},
		NoFSRestrict: true,
	}
	profile := generateSBPL(plan)
	assert.Contains(t, profile, "(deny network* (socket-domain AF_UNIX))")
}

func TestGenerateSBPL_AFUnixAllowed(t *testing.T) {
	plan := &SandboxPlan{
		Caps:             &Capabilities{},
		AllowUnixSockets: true,
		NoFSRestrict:     true,
	}
	profile := generateSBPL(plan)
	assert.NotContains(t, profile, "AF_UNIX")
}

func TestGenerateSBPL_PTY(t *testing.T) {
	plan := &SandboxPlan{
		Caps:         &Capabilities{},
		NoFSRestrict: true,
	}
	profile := generateSBPL(plan)
	assert.Contains(t, profile, "(allow pseudo-tty)")
	assert.Contains(t, profile, `/dev/ptmx`)
}

func TestCollectAncestors(t *testing.T) {
	ancestors := collectAncestors([]string{"/private/var/secrets/key"})
	assert.Contains(t, ancestors, "/private/var/secrets")
	assert.Contains(t, ancestors, "/private/var")
	assert.Contains(t, ancestors, "/private")
	// Root should not be included.
	assert.NotContains(t, ancestors, "/")
}

func TestGenerateSBPL_BaseMachServices(t *testing.T) {
	plan := &SandboxPlan{
		Caps:         &Capabilities{},
		NoFSRestrict: true,
	}
	profile := generateSBPL(plan)
	// Base services should always be present.
	assert.Contains(t, profile, `"com.apple.system.opendirectoryd.libinfo"`)
	assert.Contains(t, profile, `"com.apple.logd"`)
	// Network services should not be present without network access.
	assert.NotContains(t, profile, `"com.apple.SecurityServer"`)
}

func TestGenerateSBPL_FullProfile(t *testing.T) {
	plan := &SandboxPlan{
		Caps:           &Capabilities{},
		ROPaths:        []string{"/usr", "/System"},
		ROFiles:        []string{"/private/etc/hosts"},
		RWPaths:        []string{"/private/tmp/curb-abc"},
		RWFiles:        []string{"/dev/null"},
		ExecPaths:      []string{"/usr/bin"},
		HiddenPaths:    []string{"/private/etc/passwd"},
		ProxyEnabled:   true,
		ProxyPort:      55555,
		AllowedDomains: []string{"example.com"},
		NoFSRestrict:   false,
	}
	profile := generateSBPL(plan)

	// Verify section ordering: process before read before write before deny before network.
	procIdx := strings.Index(profile, ";; Process.")
	readIdx := strings.Index(profile, ";; Read-only paths.")
	writeIdx := strings.Index(profile, ";; Read-write paths.")
	denyIdx := strings.Index(profile, ";; Denials.")
	netIdx := strings.Index(profile, ";; Network.")

	assert.Greater(t, readIdx, procIdx, "read should follow process")
	assert.Greater(t, writeIdx, readIdx, "write should follow read")
	assert.Greater(t, denyIdx, writeIdx, "deny should follow write")
	assert.Greater(t, netIdx, denyIdx, "network should follow deny")
}
