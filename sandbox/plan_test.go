//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
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
	return &config.Config{}
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
	cfg := &config.Config{NoFSRestrict: true, NoExecRestrict: true}
	plan, err := BuildPlan(cfg, caps)
	require.NoError(t, err)
	defer plan.Cleanup()
}

func TestBuildPlan_NoExecRestrict(t *testing.T) {
	cfg := &config.Config{NoExecRestrict: true}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.False(t, hasDegradedLayer(plan, "exec"), "user-chosen --exec '*' should not be a degraded layer")
}

func TestBuildPlan_ExecRemoveAll(t *testing.T) {
	cfg := &config.Config{ExecAllow: []string{"!*"}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()
	assert.Nil(t, plan.ExecPaths)
}

func TestBuildPlan_ExecAbsPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, nil, 0o755))

	cfg := &config.Config{ExecAllow: []string{bin}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()
	assert.Contains(t, plan.ExecPaths, bin)
}

// chdirTemp changes to dir and restores the original working directory on cleanup.
func chdirTemp(t *testing.T, dir string) {
	t.Helper()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })
}

func TestBuildPlan_ExecRelativePath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mybin"), nil, 0o755))
	chdirTemp(t, dir)

	cfg := &config.Config{ExecAllow: []string{"./mybin"}}
	plan, planErr := BuildPlan(cfg, minCaps())
	require.NoError(t, planErr)
	defer plan.Cleanup()
	assert.Contains(t, plan.ExecPaths, filepath.Join(dir, "mybin"))
}

func TestBuildPlan_ExecRelativeGlob(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "dist", "linux_amd64")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	bin := filepath.Join(sub, "mybinary")
	require.NoError(t, os.WriteFile(bin, nil, 0o755))
	chdirTemp(t, dir)

	cfg := &config.Config{ExecAllow: []string{"./dist/*/*"}}
	plan, planErr := BuildPlan(cfg, minCaps())
	require.NoError(t, planErr)
	defer plan.Cleanup()
	assert.Contains(t, plan.ExecPaths, bin)
}

func TestBuildPlan_ExecRelativeGlobNoMatch(t *testing.T) {
	dir := t.TempDir()
	chdirTemp(t, dir)

	cfg := &config.Config{ExecAllow: []string{"./nonexistent/*"}}
	_, planErr := BuildPlan(cfg, minCaps())
	require.Error(t, planErr)
	assert.Contains(t, planErr.Error(), "no matches found")
}

func TestBuildPlan_ExecNotFound(t *testing.T) {
	cfg := &config.Config{ExecAllow: []string{"nonexistent-binary-xyz"}}
	_, err := BuildPlan(cfg, minCaps())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--exec nonexistent-binary-xyz: not found in PATH")
}

func TestBuildPlan_AllowLocalhost(t *testing.T) {
	cfg := &config.Config{AllowedDomains: []string{"localhost"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.AllowLocalhost)
}

func TestBuildPlan_WildcardDomainAllowsLocalhost(t *testing.T) {
	cfg := &config.Config{AllowedDomains: []string{"*"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.AllowLocalhost)
}

func TestBuildPlan_NoUserNS_LandlockAvailable(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 4}
	cfg := &config.Config{UnrestrictedNet: true}
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
	cfg := &config.Config{AllowedDomains: []string{"example.com"}}
	_, err := BuildPlan(cfg, caps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--domains/--ips require user namespaces")
}

func TestBuildPlan_NoUserNS_WithIPs(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 4}
	cfg := &config.Config{AllowedIPs: []string{"10.0.0.1"}}
	_, err := BuildPlan(cfg, caps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--domains/--ips require user namespaces")
}

func TestBuildPlan_NoFSRestrict(t *testing.T) {
	cfg := &config.Config{NoFSRestrict: true}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.False(t, hasDegradedLayer(plan, "filesystem"), "user-chosen --write '*' should not be a degraded layer")
}

// --- BuildPlan IPs + UnrestrictedNet ---

func TestBuildPlan_IPsEnableNet(t *testing.T) {
	cfg := &config.Config{AllowedIPs: []string{"10.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.ProxyEnabled)
	assert.Equal(t, []string{"10.0.0.1"}, plan.AllowedIPs)
}

func TestBuildPlan_IPsAndDomainsEnableNet(t *testing.T) {
	cfg := &config.Config{AllowedDomains: []string{"example.com"}, AllowedIPs: []string{"10.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.ProxyEnabled)
}

func TestBuildPlan_UnrestrictedNet(t *testing.T) {
	cfg := &config.Config{UnrestrictedNet: true}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()
	assert.True(t, plan.UnrestrictedNet)
	assert.False(t, plan.ProxyEnabled)
}

func TestBuildPlan_IPsLoopbackImpliesAllowLocalhost(t *testing.T) {
	cfg := &config.Config{AllowedIPs: []string{"127.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.AllowLocalhost)
}

func TestBuildPlan_IPsNoLoopback(t *testing.T) {
	cfg := &config.Config{AllowedIPs: []string{"10.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.False(t, plan.AllowLocalhost)
}

func TestBuildPlan_ChildConfig_AllowedIPs(t *testing.T) {
	cfg := &config.Config{AllowedIPs: []string{"10.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps())
	if err != nil {
		t.Skip("network namespaces not available:", err)
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

	cfg := &config.Config{ROPaths: []string{link}}
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

	cfg := &config.Config{RWPaths: []string{link}}
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

	cfg := &config.Config{ROPaths: []string{"!*"}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.NotContains(t, plan.ROPaths, cwd)
}

func TestBuildPlan_CWDExcludedByName(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := &config.Config{ROPaths: []string{"!" + cwd}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.NotContains(t, plan.ROPaths, cwd)
}

func TestBuildPlan_CWDExcludedByDot(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := &config.Config{ROPaths: []string{"!."}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.NotContains(t, plan.ROPaths, cwd)
}

func TestBuildPlan_RelativeWritePathResolved(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := &config.Config{RWPaths: []string{"."}}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	// "." must be resolved to the absolute CWD, not kept as a relative path.
	assert.Contains(t, plan.RWPaths, cwd, "CWD should appear as absolute path")
	for _, p := range plan.RWPaths {
		assert.True(t, filepath.IsAbs(p), "all RWPaths must be absolute, got %q", p)
	}
}

func TestResolveSymlinks_RelativePathsAbsolute(t *testing.T) {
	result := resolveSymlinks([]string{".", "/usr"})
	for _, p := range result {
		assert.True(t, filepath.IsAbs(p), "resolveSymlinks must return absolute paths, got %q", p)
	}
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
	plan := &SandboxPlan{SandboxHome: "/tmp"}
	applyEnvPolicy(plan, cfg, "/tmp")

	assert.Empty(t, plan.EnvSet)
	assert.Empty(t, plan.SandboxHome, "!* should clear SandboxHome to suppress HOME fallback")
	// ResolveEnv should not add HOME back.
	env := plan.ResolveEnv()
	for _, e := range env {
		assert.NotContains(t, e, "HOME=", "HOME should not appear after !*")
	}
}

func TestApplyEnvPolicy_EnvRemoveSome(t *testing.T) {
	// !TMPDIR removes TMPDIR from the default EnvSet.
	cfg := &config.Config{EnvPassthrough: []string{"!TMPDIR"}}
	plan := &SandboxPlan{}
	applyEnvPolicy(plan, cfg, "/tmp")

	_, ok := plan.EnvSet["TMPDIR"]
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

// --- resolveSandboxHome ---

func TestResolveSandboxHome_ExplicitSet(t *testing.T) {
	cfg := &config.Config{EnvSet: []string{"HOME=/custom/home"}}
	home := resolveSandboxHome(cfg, "/tmp/curb-xxx")
	assert.Equal(t, "/custom/home", home)
}

func TestResolveSandboxHome_Passthrough(t *testing.T) {
	t.Setenv("HOME", "/host/home")
	cfg := &config.Config{EnvPassthrough: []string{"HOME"}}
	home := resolveSandboxHome(cfg, "/tmp/curb-xxx")
	assert.Equal(t, "/host/home", home)
}

func TestResolveSandboxHome_RemoveAllThenAddHome(t *testing.T) {
	// --env '!*' --env HOME should still pass through HOME.
	t.Setenv("HOME", "/host/home")
	cfg := &config.Config{EnvPassthrough: []string{"!*", "HOME"}}
	home := resolveSandboxHome(cfg, "/tmp/curb-xxx")
	assert.Equal(t, "/host/home", home)
}

func TestResolveSandboxHome_FallbackToTmpDir(t *testing.T) {
	cfg := &config.Config{}
	home := resolveSandboxHome(cfg, "/tmp/curb-xxx")
	assert.Equal(t, "/tmp/curb-xxx", home)
}

func TestResolveSandboxHome_ExplicitSetBeatsPassthrough(t *testing.T) {
	t.Setenv("HOME", "/host/home")
	cfg := &config.Config{
		EnvSet:         []string{"HOME=/explicit"},
		EnvPassthrough: []string{"HOME"},
	}
	home := resolveSandboxHome(cfg, "/tmp/curb-xxx")
	assert.Equal(t, "/explicit", home)
}

func TestResolveSandboxHome_PassthroughAllIncludesHOME(t *testing.T) {
	t.Setenv("HOME", "/host/home")
	cfg := &config.Config{EnvPassthroughAll: true}
	home := resolveSandboxHome(cfg, "/tmp/curb-xxx")
	assert.Equal(t, "/host/home", home)
}

// --- tilde expansion uses sandbox HOME ---

func TestBuildPlan_TildeExpandsToSandboxHome(t *testing.T) {
	// When HOME is passed through, ~ in paths should resolve to the host HOME
	// (which equals sandbox HOME since HOME is passed through).
	t.Setenv("HOME", "/host/home")
	cfg := &config.Config{
		ROPaths:        []string{"~/.ssh"},
		EnvPassthrough: []string{"HOME"},
	}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Contains(t, plan.ROPaths, "/host/home/.ssh")
}

func TestBuildPlan_TildeExpandsToTmpDirWhenNoHome(t *testing.T) {
	// When HOME is not passed through, ~ resolves to tmpDir.
	cfg := &config.Config{
		ROPaths: []string{"~/.config"},
	}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	// ~ should have expanded to tmpDir, not os.UserHomeDir().
	hostHome, _ := os.UserHomeDir()
	assert.NotContains(t, plan.ROPaths, hostHome+"/.config",
		"~ must not expand to host home when HOME is not passed through")

	expected := plan.TempDir + "/.config"
	assert.Contains(t, plan.ROPaths, expected,
		"~ should expand to sandbox HOME (tmpDir)")
}

func TestBuildPlan_TildeExpandsToExplicitHome(t *testing.T) {
	cfg := &config.Config{
		ROPaths: []string{"~/.ssh"},
		EnvSet:  []string{"HOME=/custom"},
	}
	plan, err := BuildPlan(cfg, minCaps())
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Contains(t, plan.ROPaths, "/custom/.ssh")
}

// --- ResolveEnv HOME fallback ---

func TestResolveEnv_HomeFallbackToSandboxHome(t *testing.T) {
	// When HOME is not set in EnvSet and not in passthrough, ResolveEnv
	// should add HOME from SandboxHome.
	plan := &SandboxPlan{
		TempDir:     "/tmp/curb-test",
		SandboxHome: "/tmp/curb-test",
		EnvSet:      map[string]string{"TMPDIR": "/tmp/curb-test"},
	}
	env := plan.ResolveEnv()
	var homeVal string
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == "HOME" {
			homeVal = v
		}
	}
	assert.Equal(t, "/tmp/curb-test", homeVal, "HOME should fall back to SandboxHome")
}

func TestResolveEnv_HomePassthroughOverridesFallback(t *testing.T) {
	// When HOME is in passthrough, the host value should be used,
	// not the SandboxHome fallback.
	t.Setenv("HOME", "/host/home")
	plan := &SandboxPlan{
		TempDir:        "/tmp/curb-test",
		SandboxHome:    "/host/home",
		EnvSet:         map[string]string{"TMPDIR": "/tmp/curb-test"},
		EnvPassthrough: []string{"HOME"},
	}
	env := plan.ResolveEnv()
	var homeVal string
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == "HOME" {
			homeVal = v
		}
	}
	assert.Equal(t, "/host/home", homeVal, "passthrough HOME should override fallback")
}

func TestResolveEnv_HomeExplicitSet(t *testing.T) {
	plan := &SandboxPlan{
		TempDir: "/tmp/curb-test",
		EnvSet:  map[string]string{"TMPDIR": "/tmp/curb-test", "HOME": "/explicit"},
	}
	env := plan.ResolveEnv()
	var homeVal string
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok && k == "HOME" {
			homeVal = v
		}
	}
	assert.Equal(t, "/explicit", homeVal)
}
