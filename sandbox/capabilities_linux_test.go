//go:build linux

package sandbox

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/upsun/curb/config"
)

func TestProbeAll_ReturnsResults(t *testing.T) {
	caps := ProbeAll()

	// On a modern Linux system, user namespaces should be available.
	// However, we can't guarantee this in all CI environments,
	// so just verify the struct is populated.
	assert.NotEmpty(t, caps.KernelInfo, "KernelInfo should be populated")

	// LandlockABI should be >= 0 (0 means unavailable, >0 means version).
	assert.GreaterOrEqual(t, caps.LandlockABI, 0)
}

func TestBuildPlan_FullCapabilities(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		MountNS:     nil,
		NetNS:       nil,
		TUN:         nil,
		LandlockABI: 4,
		KernelInfo:  "6.8.0-test",
	}
	cfg := &config.Config{
		ROPaths:   []string{"/extra"},
		ExecAllow: []string{"/usr/bin/rg"},
		DryRun:    true,
	}

	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Empty(t, plan.DegradedLayers, "full caps should have no degraded layers")
	assert.True(t, plan.UsePivotRoot, "mount NS available means pivot_root")
	assert.True(t, plan.UseLandlock, "landlock available means landlock hardening")
	assert.Contains(t, plan.ROPaths, "/extra")
	assert.Contains(t, plan.ExecPaths, "/usr/bin/rg")
	assert.NotEmpty(t, plan.TempDir)
	assert.False(t, plan.NetEnabled, "no --allow means no network")
}

func TestBuildPlan_NoLandlock_MountNSAvailable(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		MountNS:     nil,
		LandlockABI: 0,
		KernelInfo:  "5.10.0-test",
	}
	cfg := &config.Config{}

	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err, "mount NS available: should use pivot_root without landlock")
	defer plan.Cleanup()
	assert.True(t, plan.UsePivotRoot)
	assert.False(t, plan.UseLandlock)
}

func TestBuildPlan_BothUnavailable_Fatal(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		MountNS:     assert.AnError,
		LandlockABI: 0,
		KernelInfo:  "4.0.0-test",
	}
	cfg := &config.Config{}

	_, err := BuildPlan(cfg, caps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mount namespaces and landlock both unavailable")
}

func TestBuildPlan_NoMountNS_LandlockOnly(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		MountNS:     assert.AnError,
		LandlockABI: 4,
		KernelInfo:  "6.8.0-test",
	}
	cfg := &config.Config{}

	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.False(t, plan.UsePivotRoot)
	assert.True(t, plan.UseLandlock)
	assert.False(t, hasDegradedLayer(plan, "mount namespace"),
		"mount namespace unavailability is not a degraded layer")
}

// TestBuildPlan_NoMountNS_SubpathDenialWarns verifies that sub-path denials
// warn (not error) when mount namespaces are unavailable.
func TestBuildPlan_NoMountNS_SubpathDenialWarns(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		MountNS:     assert.AnError,
		LandlockABI: 4,
		KernelInfo:  "6.8.0-test",
	}
	// --read /etc --read '!/etc/shadow': the denial is a sub-path of /etc.
	cfg := &config.Config{
		ROPaths: []string{"/etc", "!/etc/shadow"},
	}

	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err, "sub-path denials should warn, not error")
	defer plan.Cleanup()
	assert.Contains(t, plan.HiddenPaths, "/etc/shadow")
	assert.False(t, plan.UsePivotRoot)
}

func TestBuildPlan_FatalUserNS(t *testing.T) {
	caps := &Capabilities{
		UserNS: assert.AnError,
	}
	cfg := &config.Config{}

	plan, err := BuildPlan(cfg, caps)
	assert.Error(t, err)
	assert.Nil(t, plan)
	assert.Contains(t, err.Error(), "fatal")
	assert.Contains(t, err.Error(), "User namespaces")
}

func TestBuildPlan_FatalNetNS(t *testing.T) {
	caps := &Capabilities{
		UserNS: nil,
		NetNS:  assert.AnError,
	}
	cfg := &config.Config{
		AllowedDomains: []string{"example.com"},
	}

	plan, err := BuildPlan(cfg, caps)
	assert.Error(t, err)
	assert.Nil(t, plan)
	assert.Contains(t, err.Error(), "fatal")
}

func TestBuildPlan_FatalTUN(t *testing.T) {
	caps := &Capabilities{
		UserNS: nil,
		NetNS:  nil,
		TUN:    assert.AnError,
	}
	cfg := &config.Config{
		AllowedDomains: []string{"example.com"},
	}

	plan, err := BuildPlan(cfg, caps)
	assert.Error(t, err)
	assert.Nil(t, plan)
	assert.Contains(t, err.Error(), "/dev/net/tun")
}

func TestBuildPlan_NetNotFatalWithoutAllow(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		NetNS:       assert.AnError,
		TUN:         assert.AnError,
		LandlockABI: 4,
	}
	cfg := &config.Config{}

	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err, "net errors are not fatal without --allow")
	defer plan.Cleanup()
	assert.False(t, plan.NetEnabled)
}

func TestBuildPlan_EnvPolicy(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		LandlockABI: 4,
	}
	cfg := &config.Config{
		EnvSet:         []string{"FOO=bar"},
		EnvPassthrough: []string{"GOPATH"},
	}

	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Equal(t, "bar", plan.EnvSet["FOO"])
	assert.Equal(t, "1", plan.EnvSet["IS_SANDBOX"])
	assert.Contains(t, plan.EnvPassthrough, "GOPATH")
	assert.Contains(t, plan.EnvPassthrough, "TERM")
}

func TestPrintDryRun_ContainsExpectedSections(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		MountNS:     nil,
		NetNS:       nil,
		TUN:         nil,
		LandlockABI: 4,
		KernelInfo:  "6.8.0-test",
	}
	cfg := &config.Config{
		AllowedDomains: []string{"example.com"},
	}

	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err)
	defer plan.Cleanup()

	var buf bytes.Buffer
	plan.PrintDryRun(&buf)
	output := buf.String()

	assert.Contains(t, output, "curb: system capabilities")
	assert.Contains(t, output, "user namespaces:")
	assert.Contains(t, output, "ok (kernel 6.8.0-test)")
	assert.Contains(t, output, "landlock:")
	assert.Contains(t, output, "ABI v4")
	assert.Contains(t, output, "curb: sandbox plan")
	assert.Contains(t, output, "filesystem:")
	assert.Contains(t, output, "network:")
	assert.Contains(t, output, "example.com")
	assert.Contains(t, output, "environment:")
	assert.Contains(t, output, "method:     pivot_root + landlock")
	assert.Contains(t, output, "status:     full")
}

func TestPrintDryRun_DegradedEnforcement(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		PidNS:       assert.AnError,
		LandlockABI: 4,
		KernelInfo:  "5.10.0-test",
	}
	cfg := &config.Config{}

	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err)
	defer plan.Cleanup()

	var buf bytes.Buffer
	plan.PrintDryRun(&buf)
	output := buf.String()

	assert.Contains(t, output, "status:     degraded")
	assert.Contains(t, output, "warning: pid namespace:")
}
