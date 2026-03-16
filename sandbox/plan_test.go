//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/upsun/curb/config"
)

// hasDegradedLayer reports whether the plan has a degraded layer with the given name.
func hasDegradedLayer(plan *SandboxPlan, layer string) bool {
	for _, d := range plan.DegradedLayers {
		if d.Layer == layer {
			return true
		}
	}
	return false
}

// minCaps returns a Capabilities struct that allows BuildPlan to succeed.
func minCaps() *Capabilities {
	return &Capabilities{LandlockABI: 3}
}

// minCfg returns a minimal Config suitable for BuildPlan.
func minCfg() *config.Config {
	return &config.Config{
		ECHMode: "strip",
	}
}

// --- splitDirsFiles ---

func TestSplitDirsFiles(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "file.txt")
	require.NoError(t, os.WriteFile(f, nil, 0o644))

	dirs, files := splitDirsFiles([]string{dir, f, "/nonexistent/path"})
	assert.Equal(t, []string{dir, "/nonexistent/path"}, dirs, "dirs and non-existent paths")
	assert.Equal(t, []string{f}, files, "regular files")
}

// --- appendExecDirs ---

func TestAppendExecDirs(t *testing.T) {
	tests := []struct {
		name      string
		roPaths   []string
		execPaths []string
		want      string
		wantNot   string
	}{
		{"adds parent dir", []string{"/usr/lib"}, []string{"/usr/bin/foo"}, "/usr/bin", ""},
		{"skips root", []string{}, []string{"/foo"}, "", "/"},
		{"skips covered by prefix", []string{"/usr"}, []string{"/usr/bin/foo"}, "", "/usr/bin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendExecDirs(tt.roPaths, tt.execPaths)
			if tt.want != "" {
				assert.Contains(t, result, tt.want)
			}
			if tt.wantNot != "" {
				assert.NotContains(t, result, tt.wantNot)
			}
		})
	}
}

// --- resolveSymlinks ---

func TestResolveSymlinks_WithSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-binary")
	link := filepath.Join(dir, "link-binary")
	require.NoError(t, os.WriteFile(target, nil, 0o755))
	require.NoError(t, os.Symlink(target, link))

	result := resolveSymlinks([]string{link})
	assert.Contains(t, result, link)
	assert.Contains(t, result, target)
}

func TestResolveSymlinks_DirectorySymlink(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real-dir")
	require.NoError(t, os.Mkdir(realDir, 0o755))
	link := filepath.Join(dir, "link-dir")
	require.NoError(t, os.Symlink(realDir, link))

	result := resolveSymlinks([]string{link})
	assert.Contains(t, result, link)
	assert.Contains(t, result, realDir)
}

func TestResolveSymlinks_NoSymlink(t *testing.T) {
	dir := t.TempDir()
	result := resolveSymlinks([]string{dir})
	assert.Equal(t, []string{dir}, result, "non-symlink path unchanged")
}

func TestResolveSymlinks_NonExistentPath(t *testing.T) {
	result := resolveSymlinks([]string{"/nonexistent/path/xyz"})
	assert.Equal(t, []string{"/nonexistent/path/xyz"}, result, "non-existent path kept")
}

func TestResolveSymlinks_NoDuplicates(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(target, 0o755))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))

	// Both the symlink and its target are already in the list.
	result := resolveSymlinks([]string{link, target})
	assert.Equal(t, []string{link, target}, result, "no duplicates added")
}

// --- Cleanup ---

func TestCleanup_RemovesTempDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "curb-test")
	require.NoError(t, os.Mkdir(sub, 0o755))

	plan := &SandboxPlan{TempDir: sub}
	plan.Cleanup()

	_, err := os.Stat(sub)
	assert.True(t, os.IsNotExist(err))
}

// --- buildDegradedPlan ---

func TestBuildDegradedPlan_FSAndExecDegraded(t *testing.T) {
	cfg := &config.Config{}
	plan, err := buildDegradedPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.True(t, hasDegradedLayer(plan, "filesystem restrictions"))
	assert.True(t, hasDegradedLayer(plan, "executable control"))
}

func TestBuildDegradedPlan_WithDomains(t *testing.T) {
	cfg := &config.Config{
		AllowedDomains: []string{"example.com"},
		NoFSRestrict:   true,
		NoExecRestrict: true,
	}
	plan, err := buildDegradedPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.True(t, hasDegradedLayer(plan, "network filtering"))
}

func TestBuildDegradedPlan_NoISandboxEnv(t *testing.T) {
	cfg := &config.Config{NoFSRestrict: true, NoExecRestrict: true}
	plan, err := buildDegradedPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	_, ok := plan.EnvSet["IS_SANDBOX"]
	assert.False(t, ok, "IS_SANDBOX should not be set for non-isolated platforms")
}

// --- BuildPlan ---

func TestBuildPlan_NoLandlock_WithMountNS(t *testing.T) {
	caps := &Capabilities{LandlockABI: 0} // MountNS is nil = available.
	plan, err := BuildPlan(minCfg(), caps)
	require.NoError(t, err, "should succeed with pivot_root when mount NS available")
	defer plan.Cleanup()
	assert.True(t, plan.UsePivotRoot)
	assert.False(t, plan.UseLandlock)
}

func TestBuildPlan_NoLandlock_NoFSRestrict(t *testing.T) {
	caps := &Capabilities{LandlockABI: 0}
	cfg := &config.Config{ECHMode: "strip", NoFSRestrict: true, NoExecRestrict: true}
	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err)
	defer plan.Cleanup()
}

func TestBuildPlan_NoExecRestrict(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", NoExecRestrict: true}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.False(t, hasDegradedLayer(plan, "exec"), "user-chosen --exec '*' should not be a degraded layer")
}

func TestBuildPlan_ExecRemoveAll(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", ExecAllow: []string{"!*"}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()
	assert.Nil(t, plan.ExecPaths)
}

func TestBuildPlan_ExecAbsPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, nil, 0o755))

	cfg := &config.Config{ECHMode: "strip", ExecAllow: []string{bin}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()
	assert.Contains(t, plan.ExecPaths, bin)
}

func TestBuildPlan_ExecNotFound(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", ExecAllow: []string{"nonexistent-binary-xyz"}}
	_, err := BuildPlan(cfg, minCaps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--exec nonexistent-binary-xyz: not found in PATH")
}

func TestBuildPlan_AllowLocalhost(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", AllowedDomains: []string{"localhost"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces or TUN not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.AllowLocalhost)
}

func TestBuildPlan_WildcardDomainAllowsLocalhost(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", AllowedDomains: []string{"*"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces or TUN not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.AllowLocalhost)
}

func TestBuildPlan_NoUserNS_LandlockAvailable(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 4}
	cfg := &config.Config{ECHMode: "strip", UnrestrictedNet: true}
	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err)
	defer plan.Cleanup()
	assert.True(t, plan.NoUserNS)
	assert.True(t, plan.UseLandlock)
	assert.True(t, plan.UnrestrictedNet)
	assert.False(t, plan.UsePivotRoot)
	assert.False(t, plan.PidNS)
	assert.True(t, hasDegradedLayer(plan, "user namespace"))
}

func TestBuildPlan_NoUserNS_RequiresUnrestrictedNet(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 4}
	_, err := BuildPlan(minCfg(), caps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--unrestricted-net")
}

func TestBuildPlan_NoUserNS_NoLandlock(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 0}
	_, err := BuildPlan(minCfg(), caps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fatal")
	assert.Contains(t, err.Error(), "Landlock")
}

func TestBuildPlan_NoUserNS_WithDomains(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 4}
	cfg := &config.Config{ECHMode: "strip", AllowedDomains: []string{"example.com"}}
	_, err := BuildPlan(cfg, caps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--domains/--ips require user namespaces")
}

func TestBuildPlan_NoUserNS_WithIPs(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 4}
	cfg := &config.Config{ECHMode: "strip", AllowedIPs: []string{"10.0.0.1"}}
	_, err := BuildPlan(cfg, caps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--domains/--ips require user namespaces")
}

func TestBuildPlan_NoFSRestrict(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", NoFSRestrict: true}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.False(t, hasDegradedLayer(plan, "filesystem"), "user-chosen --write '*' should not be a degraded layer")
}

// --- BuildPlan IPs + UnrestrictedNet ---

func TestBuildPlan_IPsEnableNet(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", AllowedIPs: []string{"10.0.0.1"}, ProxyMode: "off"}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces or TUN not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.NetEnabled)
	assert.Equal(t, []string{"10.0.0.1"}, plan.AllowedIPs)
}

func TestBuildPlan_IPsAndDomainsEnableNet(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", AllowedDomains: []string{"example.com"}, AllowedIPs: []string{"10.0.0.1"}, ProxyMode: "off"}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces or TUN not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.NetEnabled)
}

func TestBuildPlan_UnrestrictedNet(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", UnrestrictedNet: true}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()
	assert.True(t, plan.UnrestrictedNet)
	assert.False(t, plan.NetEnabled)
}

func TestBuildPlan_IPsLoopbackImpliesAllowLocalhost(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", AllowedIPs: []string{"127.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces or TUN not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.AllowLocalhost)
}

func TestBuildPlan_IPsNoLoopback(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", AllowedIPs: []string{"10.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces or TUN not available:", err)
	}
	defer plan.Cleanup()
	assert.False(t, plan.AllowLocalhost)
}

func TestBuildPlan_ChildConfig_AllowedIPs(t *testing.T) {
	cfg := &config.Config{ECHMode: "strip", AllowedIPs: []string{"10.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces or TUN not available:", err)
	}
	defer plan.Cleanup()
	cc := plan.childConfig()
	assert.Equal(t, []string{"10.0.0.1"}, cc.AllowedIPs)
}

// --- isSubpath ---

func TestIsSubpath(t *testing.T) {
	tests := []struct {
		child, parent string
		want          bool
	}{
		{"/home/user/.ssh", "/home/user", true},
		{"/home/user", "/home/user", false},  // not strict
		{"/home/user2", "/home/user", false}, // different prefix
		{"/etc/passwd", "/home/user", false},
	}
	for _, tt := range tests {
		t.Run(tt.child+"_under_"+tt.parent, func(t *testing.T) {
			assert.Equal(t, tt.want, isSubpath(tt.child, tt.parent))
		})
	}
}

// --- isExcluded ---

func TestIsExcluded(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	tests := []struct {
		name     string
		path     string
		excludes []string
		want     bool
	}{
		{"exact match", "/usr/lib", []string{"/usr/lib"}, true},
		{"no match", "/usr/lib", []string{"/usr/bin"}, false},
		{"relative dot resolves to cwd", cwd, []string{"."}, true},
		{"empty excludes", "/usr/lib", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isExcluded(tt.path, tt.excludes))
		})
	}
}

// --- BuildPlan symlink resolution ---

func TestBuildPlan_ResolvesROSymlinks(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(realDir, 0o755))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(realDir, link))

	cfg := &config.Config{ECHMode: "strip", ROPaths: []string{link}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Contains(t, plan.ROPaths, link, "original symlink kept")
	assert.Contains(t, plan.ROPaths, realDir, "resolved target added")
}

func TestBuildPlan_ResolvesRWSymlinks(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(realDir, 0o755))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(realDir, link))

	cfg := &config.Config{ECHMode: "strip", RWPaths: []string{link}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Contains(t, plan.RWPaths, link, "original symlink kept")
	assert.Contains(t, plan.RWPaths, realDir, "resolved target added")
}

// --- BuildPlan CWD ---

func TestBuildPlan_CWDIncludedByDefault(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	plan, err := BuildPlan(minCfg(), minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Contains(t, plan.ROPaths, cwd)
}

func TestBuildPlan_CWDExcludedByRemoveAll(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := &config.Config{ECHMode: "strip", ROPaths: []string{"!*"}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.NotContains(t, plan.ROPaths, cwd)
}

func TestBuildPlan_CWDExcludedByName(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := &config.Config{ECHMode: "strip", ROPaths: []string{"!" + cwd}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.NotContains(t, plan.ROPaths, cwd)
}

func TestBuildPlan_CWDExcludedByDot(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := &config.Config{ECHMode: "strip", ROPaths: []string{"!."}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.NotContains(t, plan.ROPaths, cwd)
}

// --- setupShellInit ---

func TestSetupShellInit_Bash(t *testing.T) {
	tmpDir := t.TempDir()
	plan := &SandboxPlan{
		Command: []string{"/bin/bash"},
		EnvSet:  map[string]string{},
	}
	require.NoError(t, setupShellInit(plan, tmpDir))
	assert.Equal(t, "/bin/bash", plan.Command[0])
	assert.Equal(t, "--rcfile", plan.Command[1])
	rcFile := plan.Command[2]
	content, err := os.ReadFile(rcFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "(curb)")
	assert.Contains(t, string(content), ".bashrc")
}

func TestSetupShellInit_BashSkipDashC(t *testing.T) {
	tmpDir := t.TempDir()
	plan := &SandboxPlan{
		Command: []string{"bash", "-c", "echo hi"},
		EnvSet:  map[string]string{},
	}
	require.NoError(t, setupShellInit(plan, tmpDir))
	// -c means non-interactive: no --rcfile should be inserted.
	assert.Equal(t, []string{"bash", "-c", "echo hi"}, plan.Command)
}

func TestSetupShellInit_Zsh(t *testing.T) {
	tmpDir := t.TempDir()
	plan := &SandboxPlan{
		Command: []string{"/usr/bin/zsh"},
		EnvSet:  map[string]string{},
	}
	require.NoError(t, setupShellInit(plan, tmpDir))
	assert.Equal(t, tmpDir, plan.EnvSet["ZDOTDIR"])
	// Command is not modified for zsh.
	assert.Equal(t, []string{"/usr/bin/zsh"}, plan.Command)
	// .zshrc should exist and contain (curb).
	content, err := os.ReadFile(filepath.Join(tmpDir, ".zshrc"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "(curb)")
	// .zshenv should forward the original.
	_, err = os.Stat(filepath.Join(tmpDir, ".zshenv"))
	assert.NoError(t, err)
}

func TestSetupShellInit_OtherShell(t *testing.T) {
	tmpDir := t.TempDir()
	plan := &SandboxPlan{
		Command: []string{"/bin/sh"},
		EnvSet:  map[string]string{},
	}
	require.NoError(t, setupShellInit(plan, tmpDir))
	// No modifications for unknown shells.
	assert.Equal(t, []string{"/bin/sh"}, plan.Command)
}

// --- applyEnvPolicy ---

func TestApplyEnvPolicy_EnvRemoveAll(t *testing.T) {
	cfg := &config.Config{EnvPassthrough: []string{"!*"}}
	plan := &SandboxPlan{}
	applyEnvPolicy(plan, cfg, "/tmp")

	assert.Empty(t, plan.EnvSet)
}

func TestApplyEnvPolicy_EnvRemoveSome(t *testing.T) {
	cfg := &config.Config{EnvPassthrough: []string{"!HOME"}}
	plan := &SandboxPlan{}
	applyEnvPolicy(plan, cfg, "/tmp")

	_, ok := plan.EnvSet["HOME"]
	assert.False(t, ok)
}

func TestApplyEnvPolicy_EnvSet(t *testing.T) {
	cfg := &config.Config{EnvSet: []string{"MY_KEY=my_val"}}
	plan := &SandboxPlan{}
	applyEnvPolicy(plan, cfg, "/tmp")

	assert.Equal(t, "my_val", plan.EnvSet["MY_KEY"])
}

// --- fsEnforcers ---

func TestFSEnforcers_NoFSRestrict(t *testing.T) {
	cfg := &ChildConfig{NoFSRestrict: true, UsePivotRoot: true, UseLandlock: true}
	assert.Nil(t, fsEnforcers(cfg))
}

func TestFSEnforcers_PivotRootOnly(t *testing.T) {
	cfg := &ChildConfig{UsePivotRoot: true}
	enforcers := fsEnforcers(cfg)
	require.Len(t, enforcers, 1)
	assert.IsType(t, &pivotRootEnforcer{}, enforcers[0])
}

func TestFSEnforcers_LandlockOnly(t *testing.T) {
	cfg := &ChildConfig{UseLandlock: true}
	enforcers := fsEnforcers(cfg)
	require.Len(t, enforcers, 1)
	assert.IsType(t, &landlockEnforcer{}, enforcers[0])
}

func TestFSEnforcers_Both(t *testing.T) {
	cfg := &ChildConfig{UsePivotRoot: true, UseLandlock: true}
	enforcers := fsEnforcers(cfg)
	require.Len(t, enforcers, 2)
	assert.IsType(t, &pivotRootEnforcer{}, enforcers[0], "pivot_root first")
	assert.IsType(t, &landlockEnforcer{}, enforcers[1], "landlock second")
}

func TestFSEnforcers_Neither(t *testing.T) {
	cfg := &ChildConfig{}
	assert.Nil(t, fsEnforcers(cfg))
}

func TestApplyEnvPolicy_PassthroughAll(t *testing.T) {
	cfg := &config.Config{EnvPassthroughAll: true}
	plan := &SandboxPlan{}
	applyEnvPolicy(plan, cfg, "/tmp")

	assert.Equal(t, []string{envPassthroughAll}, plan.EnvPassthrough)
}

func TestApplyEnvPolicy_EnvRemoveAllWithAdds(t *testing.T) {
	cfg := &config.Config{EnvPassthrough: []string{"!*", "GOPATH"}}
	plan := &SandboxPlan{}
	applyEnvPolicy(plan, cfg, "/tmp")

	assert.Equal(t, []string{"GOPATH"}, plan.EnvPassthrough)
}
