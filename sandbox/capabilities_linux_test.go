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
	assert.Contains(t, plan.ROPaths, "/extra")
	assert.Contains(t, plan.ExecPaths, "/usr/bin/rg")
	assert.NotEmpty(t, plan.TempDir)
	assert.False(t, plan.NetEnabled, "no --allow means no network")
}

func TestBuildPlan_NoLandlock(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		MountNS:     nil,
		LandlockABI: 0,
		KernelInfo:  "5.10.0-test",
	}
	cfg := &config.Config{}

	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Len(t, plan.DegradedLayers, 1)
	assert.Equal(t, "landlock", plan.DegradedLayers[0].Layer)
}

func TestBuildPlan_NoMountNS_NoHide(t *testing.T) {
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

	// Without --hide, mount NS unavailability is not degraded.
	assert.Empty(t, plan.DegradedLayers)
}

func TestBuildPlan_NoMountNS_WithHide(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		MountNS:     assert.AnError,
		LandlockABI: 4,
		KernelInfo:  "6.8.0-test",
	}
	cfg := &config.Config{
		HiddenPaths: []string{"/tmp/test"},
	}

	_, err := BuildPlan(cfg, caps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--hide requires mount namespaces")
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
	assert.Contains(t, err.Error(), "unprivileged_userns_clone")
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
	assert.Contains(t, output, "enforcement: full")
}

func TestPrintDryRun_DegradedEnforcement(t *testing.T) {
	caps := &Capabilities{
		UserNS:      nil,
		LandlockABI: 0,
		KernelInfo:  "5.10.0-test",
	}
	cfg := &config.Config{}

	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err)
	defer plan.Cleanup()

	var buf bytes.Buffer
	plan.PrintDryRun(&buf)
	output := buf.String()

	assert.Contains(t, output, "enforcement: degraded")
	assert.Contains(t, output, "warning: landlock:")
}

func TestErrorMessages_ContainFixInstructions(t *testing.T) {
	tests := []struct {
		name    string
		message string
		expect  string
	}{
		{"userNS fix", userNSFixMessage(), "unprivileged_userns_clone"},
		{"netNS fix", netNSFixMessage(), "unprivileged_userns_clone"},
		{"TUN fix", tunFixMessage(), "/dev/net/tun"},
		{"landlock warn", landlockWarnMessage(), "kernel 5.13"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, tt.message, tt.expect)
		})
	}
}
