//go:build linux

package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateProfile_DefaultPath(t *testing.T) {
	profile := generateProfile("/usr/local/bin/curb")
	assert.Contains(t, profile, "profile curb /usr/local/bin/curb{,-test} flags=(attach_disconnected) {")
	assert.Contains(t, profile, "userns,")
	assert.Contains(t, profile, "capability sys_admin,")
	assert.Contains(t, profile, "capability net_admin,")
	assert.Contains(t, profile, "capability mac_admin,")
	assert.Contains(t, profile, "/** rwlkmix,")
	assert.Contains(t, profile, "/dev/net/tun rw,")
	assert.Contains(t, profile, "abi <abi/4.0>,")
}

func TestGenerateProfile_CustomPath(t *testing.T) {
	profile := generateProfile("/opt/curb")
	assert.Contains(t, profile, "profile curb /opt/curb{,-test} flags=(attach_disconnected) {")
	assert.NotContains(t, profile, "/usr/local/bin/curb")
}

func TestGenerateProfile_SingleSubstitution(t *testing.T) {
	profile := generateProfile("/test/path")
	// The binary path should appear exactly once (in the profile header).
	require.Equal(t, 1, strings.Count(profile, "/test/path"))
}
