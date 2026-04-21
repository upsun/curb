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
			result := appendExecDirs(tt.roPaths, tt.execPaths, "")
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
	plan, err := BuildPlan(minCfg(), caps, nil)
	require.NoError(t, err, "should succeed with pivot_root when mount NS available")
	defer plan.Cleanup()
	assert.True(t, plan.UsePivotRoot)
	assert.False(t, plan.UseLandlock)
}

func TestBuildPlan_NoLandlock_NoFSRestrict(t *testing.T) {
	caps := &Capabilities{LandlockABI: 0}
	cfg := &config.Config{NoFSRestrict: true, NoExecRestrict: true}
	plan, err := BuildPlan(cfg, caps, nil)
	require.NoError(t, err)
	defer plan.Cleanup()
}

func TestBuildPlan_NoExecRestrict(t *testing.T) {
	cfg := &config.Config{NoExecRestrict: true}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.False(t, hasDegradedLayer(plan, "exec"), "user-chosen --exec '*' should not be a degraded layer")
}

func TestBuildPlan_ExecRemoveAll(t *testing.T) {
	cfg := &config.Config{ExecAllow: []string{"!*"}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()
	// User-facing exec paths are cleared, but dynamic linker directories
	// are always included so dynamically-linked binaries still work.
	for _, p := range plan.ExecPaths {
		base := filepath.Base(p)
		assert.True(t, base == "lib" || base == "lib64",
			"unexpected exec path after !*: %s", p)
	}
}

func TestBuildPlan_ExecAbsPath(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, nil, 0o755))

	cfg := &config.Config{ExecAllow: []string{bin}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
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
	plan, planErr := BuildPlan(cfg, minCaps(), nil)
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
	plan, planErr := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, planErr)
	defer plan.Cleanup()
	assert.Contains(t, plan.ExecPaths, bin)
}

func TestBuildPlan_ExecRelativeGlobNoMatch(t *testing.T) {
	dir := t.TempDir()
	chdirTemp(t, dir)

	cfg := &config.Config{ExecAllow: []string{"./nonexistent/*"}}
	_, planErr := BuildPlan(cfg, minCaps(), nil)
	require.Error(t, planErr)
	assert.Contains(t, planErr.Error(), "no matches found")
}

func TestBuildPlan_ExecNotFound_Skipped(t *testing.T) {
	cfg := &config.Config{ExecAllow: []string{"nonexistent-binary-xyz"}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	if err != nil {
		t.Skip("sandbox setup failed:", err)
	}
	defer plan.Cleanup()
	// Missing binaries are silently skipped — they should not appear in ExecPaths.
	for _, p := range plan.ExecPaths {
		assert.NotContains(t, p, "nonexistent-binary-xyz")
	}
}

func TestBuildPlan_HostLoopback(t *testing.T) {
	cfg := &config.Config{HostLoopback: true}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.HostLoopback)
	assert.True(t, plan.ProxyEnabled)
	// NO_PROXY should not be set when HostLoopback is true.
	_, hasNoProxy := plan.EnvSet["NO_PROXY"]
	assert.False(t, hasNoProxy)
}

func TestBuildPlan_HostLoopbackWithDomains(t *testing.T) {
	cfg := &config.Config{HostLoopback: true, AllowedDomains: []string{"github.com"}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.HostLoopback)
	assert.True(t, plan.ProxyEnabled)
}

func TestBuildPlan_NoUserNS_LandlockAvailable(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 4}
	cfg := &config.Config{UnrestrictedNet: true}
	plan, err := BuildPlan(cfg, caps, nil)
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
	_, err := BuildPlan(minCfg(), caps, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--unrestricted-net")
}

func TestBuildPlan_NoUserNS_NoLandlock(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 0}
	_, err := BuildPlan(minCfg(), caps, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fatal")
	assert.Contains(t, err.Error(), "Landlock")
}

func TestBuildPlan_NoUserNS_WithDomains(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 4}
	cfg := &config.Config{AllowedDomains: []string{"example.com"}}
	_, err := BuildPlan(cfg, caps, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--domains/--ips require user namespaces")
}

func TestBuildPlan_NoUserNS_WithIPs(t *testing.T) {
	caps := &Capabilities{UserNS: assert.AnError, LandlockABI: 4}
	cfg := &config.Config{AllowedIPs: []string{"10.0.0.1"}}
	_, err := BuildPlan(cfg, caps, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--domains/--ips require user namespaces")
}

func TestBuildPlan_NoFSRestrict(t *testing.T) {
	cfg := &config.Config{NoFSRestrict: true}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.False(t, hasDegradedLayer(plan, "filesystem"), "user-chosen --write '*' should not be a degraded layer")
}

// --- BuildPlan IPs + UnrestrictedNet ---

func TestBuildPlan_IPsEnableNet(t *testing.T) {
	cfg := &config.Config{AllowedIPs: []string{"10.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.ProxyEnabled)
	assert.Equal(t, []string{"10.0.0.1"}, plan.AllowedIPs)
}

func TestBuildPlan_IPsAndDomainsEnableNet(t *testing.T) {
	cfg := &config.Config{AllowedDomains: []string{"example.com"}, AllowedIPs: []string{"10.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.True(t, plan.ProxyEnabled)
}

func TestBuildPlan_UnrestrictedNet(t *testing.T) {
	cfg := &config.Config{UnrestrictedNet: true}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()
	assert.True(t, plan.UnrestrictedNet)
	assert.False(t, plan.ProxyEnabled)
}

func TestBuildPlan_IPsWithoutHostLoopback(t *testing.T) {
	cfg := &config.Config{AllowedIPs: []string{"127.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	// HostLoopback is only set by --host-loopback, not by loopback IPs.
	assert.False(t, plan.HostLoopback)
	assert.True(t, plan.ProxyEnabled)
}

func TestBuildPlan_NoProxy_SetByDefault(t *testing.T) {
	cfg := &config.Config{AllowedDomains: []string{"example.com"}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.Equal(t, defaultNoProxy, plan.EnvSet["NO_PROXY"])
	assert.Equal(t, defaultNoProxy, plan.EnvSet["no_proxy"])
}

func TestBuildPlan_NoProxy_UserOverride(t *testing.T) {
	cfg := &config.Config{
		AllowedDomains: []string{"example.com"},
		EnvSet:         []string{"NO_PROXY=custom"},
	}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	if err != nil {
		t.Skip("network namespaces not available:", err)
	}
	defer plan.Cleanup()
	assert.Equal(t, "custom", plan.EnvSet["NO_PROXY"])
}

func TestBuildPlan_ChildConfig_AllowedIPs(t *testing.T) {
	cfg := &config.Config{AllowedIPs: []string{"10.0.0.1"}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
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
	plan, err := BuildPlan(cfg, minCaps(), nil)
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
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Contains(t, plan.RWPaths, link, "original symlink kept")
	assert.Contains(t, plan.RWPaths, realDir, "resolved target added")
}

// --- BuildPlan CWD ---

func TestBuildPlan_CWDIncludedByDefault(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	plan, err := BuildPlan(minCfg(), minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Contains(t, plan.ROPaths, cwd)
}

func TestBuildPlan_CWDExcludedByRemoveAll(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := &config.Config{ROPaths: []string{"!*"}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.NotContains(t, plan.ROPaths, cwd)
}

func TestBuildPlan_CWDExcludedByName(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := &config.Config{ROPaths: []string{"!" + cwd}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.NotContains(t, plan.ROPaths, cwd)
}

func TestBuildPlan_CWDExcludedByDot(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := &config.Config{ROPaths: []string{"!."}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.NotContains(t, plan.ROPaths, cwd)
}

func TestBuildPlan_RelativeWritePathResolved(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := &config.Config{RWPaths: []string{"."}}
	plan, err := BuildPlan(cfg, minCaps(), nil)
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
	assert.Nil(t, fsEnforcers(cfg, nil))
}

func TestFSEnforcers_PivotRootOnly(t *testing.T) {
	cfg := &ChildConfig{UsePivotRoot: true}
	enforcers := fsEnforcers(cfg, nil)
	require.Len(t, enforcers, 1)
	assert.IsType(t, &pivotRootEnforcer{}, enforcers[0])
}

func TestFSEnforcers_LandlockOnly(t *testing.T) {
	cfg := &ChildConfig{UseLandlock: true}
	enforcers := fsEnforcers(cfg, nil)
	require.Len(t, enforcers, 1)
	assert.IsType(t, &landlockEnforcer{}, enforcers[0])
}

func TestFSEnforcers_Both(t *testing.T) {
	cfg := &ChildConfig{UsePivotRoot: true, UseLandlock: true}
	enforcers := fsEnforcers(cfg, nil)
	require.Len(t, enforcers, 2)
	assert.IsType(t, &pivotRootEnforcer{}, enforcers[0], "pivot_root first")
	assert.IsType(t, &landlockEnforcer{}, enforcers[1], "landlock second")
}

func TestFSEnforcers_Neither(t *testing.T) {
	cfg := &ChildConfig{}
	assert.Nil(t, fsEnforcers(cfg, nil))
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

// --- tilde expansion uses host HOME ---

func TestBuildPlan_TildeExpandsToHostHome_WithPassthrough(t *testing.T) {
	// When HOME is passed through, sandbox HOME == host HOME and ~ aligns.
	t.Setenv("HOME", "/host/home")
	cfg := &config.Config{
		ROPaths:        []string{"~/.ssh"},
		EnvPassthrough: []string{"HOME"},
	}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Contains(t, plan.ROPaths, "/host/home/.ssh")
}

func TestBuildPlan_TildeExpandsToHostHome_WithoutPassthrough(t *testing.T) {
	// Even without HOME passthrough, ~ resolves to the host home (not tmpDir).
	// A mismatch warning is emitted because the sandbox's $HOME will differ.
	t.Setenv("HOME", "/host/home")
	cfg := &config.Config{
		ROPaths: []string{"~/.config"},
	}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Contains(t, plan.ROPaths, "/host/home/.config",
		"~ should expand to the host home")
	assert.NotContains(t, plan.ROPaths, plan.TempDir+"/.config",
		"~ must no longer expand to tmpDir")
}

func TestBuildPlan_TildeIgnoresExplicitSandboxHome(t *testing.T) {
	// --env HOME=/custom sets the sandbox's HOME but does not redirect ~ —
	// ~ is a host-side shorthand, so it still resolves to the host home.
	t.Setenv("HOME", "/host/home")
	cfg := &config.Config{
		ROPaths: []string{"~/.ssh"},
		EnvSet:  []string{"HOME=/custom"},
	}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Contains(t, plan.ROPaths, "/host/home/.ssh")
	assert.NotContains(t, plan.ROPaths, "/custom/.ssh")
}

func TestBuildPlan_TildeErrorsWhenHostHomeUnavailable(t *testing.T) {
	// If os.UserHomeDir() cannot determine HOME, tilde paths would silently
	// degrade to "/foo". BuildPlan must refuse to proceed with a clear error.
	t.Setenv("HOME", "")
	cfg := &config.Config{
		ROPaths: []string{"~/.ssh"},
	}
	_, err := BuildPlan(cfg, minCaps(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "host home")
	assert.Contains(t, err.Error(), "~")
}

func TestBuildPlan_HostHomeUnavailableOKWithoutTildes(t *testing.T) {
	// Host home being unresolvable is only an error if ~ is actually used.
	t.Setenv("HOME", "")
	cfg := &config.Config{
		ROPaths: []string{"/etc/ssl"},
	}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()
	assert.Contains(t, plan.ROPaths, "/etc/ssl")
}

func TestBuildPlan_LiteralHostHomePathDoesNotWarn(t *testing.T) {
	// A user-written literal /home/user/.ssh is the user's explicit choice;
	// the mismatch warning must not flag it. We can't easily assert on the
	// absence of a log line here, but the path must resolve unchanged.
	t.Setenv("HOME", "/host/home")
	cfg := &config.Config{
		ROPaths: []string{"/host/home/.ssh"},
	}
	plan, err := BuildPlan(cfg, minCaps(), nil)
	require.NoError(t, err)
	defer plan.Cleanup()
	assert.Contains(t, plan.ROPaths, "/host/home/.ssh")
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

// --- formatSkill / writeSkill ---

func TestFormatSkill_Full(t *testing.T) {
	plan := &SandboxPlan{
		ROPaths:        []string{"/usr", "/lib"},
		RWPaths:        []string{"/tmp/curb-abc"},
		ExecPaths:      []string{"/usr/bin/node"},
		HiddenPaths:    []string{"/home/user/.ssh/keys"},
		DenyWritePaths: []string{"/home/user/.gitconfig"},
		DenyExecPaths:  []string{"/usr/local/bin/danger"},
		AllowedDomains: []string{"github.com", "api.example.com"},
		AllowedIPs:     []string{"10.0.0.1"},
		ProxyEnabled:   true,
		ProxyPort:      12345,
		SOCKSPort:      12346,
		EnvSet: map[string]string{
			"TMPDIR":     "/tmp/curb-abc",
			"IS_SANDBOX": "1",
		},
		EnvPassthrough: []string{"TERM", "LANG"},
	}
	out := formatSkill(plan)
	assert.Contains(t, out, "name: curb")
	assert.Contains(t, out, "description: ")
	assert.Contains(t, out, "# Sandbox Constraints")
	assert.Contains(t, out, "- Read-only paths:\n  - /usr\n  - /lib")
	assert.Contains(t, out, "- Read-write paths:\n  - /tmp/curb-abc")
	assert.Contains(t, out, "- Executable:\n  - /usr/bin/node")
	assert.Contains(t, out, "- Hidden:\n  - /home/user/.ssh/keys")
	assert.Contains(t, out, "- Deny write:\n  - /home/user/.gitconfig")
	assert.Contains(t, out, "- Deny exec:\n  - /usr/local/bin/danger")
	assert.Contains(t, out, "- Allowed domains: github.com, api.example.com")
	assert.Contains(t, out, "- Allowed IPs: 10.0.0.1")
	assert.Contains(t, out, "- Proxy: 127.0.0.1:12345")
	assert.Contains(t, out, "- SOCKS5: 127.0.0.1:12346")
	assert.Contains(t, out, "  - IS_SANDBOX=1")
	assert.Contains(t, out, "  - TMPDIR=/tmp/curb-abc")
	assert.Contains(t, out, "  - TERM\n  - LANG")
}

func TestFormatSkill_Minimal(t *testing.T) {
	plan := &SandboxPlan{
		EnvSet: map[string]string{"TMPDIR": "/tmp/curb-abc"},
	}
	out := formatSkill(plan)
	assert.Contains(t, out, "## Filesystem")
	assert.Contains(t, out, "- Allowed: none")
	assert.NotContains(t, out, "- Read-only paths:")
	assert.NotContains(t, out, "- Allowed domains:")
}

func TestFormatSkill_UnrestrictedNet(t *testing.T) {
	plan := &SandboxPlan{
		UnrestrictedNet: true,
		EnvSet:          map[string]string{},
	}
	out := formatSkill(plan)
	assert.Contains(t, out, "- Mode: unrestricted")
	assert.NotContains(t, out, "- Allowed: none")
}

func TestFormatSkill_NoFSSection(t *testing.T) {
	plan := &SandboxPlan{
		NoFSRestrict:   true,
		NoExecRestrict: true,
		EnvSet:         map[string]string{},
	}
	out := formatSkill(plan)
	assert.NotContains(t, out, "## Filesystem")
}

func TestFormatSkill_ExcludesSelfEnvVar(t *testing.T) {
	plan := &SandboxPlan{
		EnvSet: map[string]string{
			"TMPDIR":              "/tmp/curb-abc",
			SkillDirEnvKey: "/tmp/curb-abc/.agents/skills/curb",
		},
	}
	out := formatSkill(plan)
	assert.NotContains(t, out, SkillDirEnvKey)
}

func TestWriteSkill(t *testing.T) {
	tmpDir := t.TempDir()
	plan := &SandboxPlan{
		ROPaths:     []string{"/usr"},
		SandboxHome: tmpDir,
		EnvSet:      map[string]string{"TMPDIR": tmpDir, "IS_SANDBOX": "1"},
	}
	require.NoError(t, writeSkill(plan, tmpDir))

	// Primary SKILL.md exists.
	primaryDir := filepath.Join(tmpDir, skillPrimaryDir)
	content, err := os.ReadFile(filepath.Join(primaryDir, "SKILL.md"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "name: curb")
	assert.Equal(t, primaryDir, plan.EnvSet[SkillDirEnvKey])

	// Symlink at .claude/skills/curb -> .agents/skills/curb.
	symlinkPath := filepath.Join(tmpDir, skillSymlinkDir)
	target, err := os.Readlink(symlinkPath)
	require.NoError(t, err)
	assert.Equal(t, "../../.agents/skills/curb", target)

	// SKILL.md is readable via the symlink.
	viaSymlink, err := os.ReadFile(filepath.Join(symlinkPath, "SKILL.md"))
	require.NoError(t, err)
	assert.Equal(t, content, viaSymlink)

	// No bind mounts needed when HOME == TempDir.
	assert.Empty(t, plan.SkillMounts)
}

func TestWriteSkill_HomePassthrough(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := t.TempDir() // Separate writable dir simulating real HOME.
	plan := &SandboxPlan{
		ROPaths:      []string{"/usr"},
		SandboxHome:  homeDir,
		UsePivotRoot: true,
		EnvSet:       map[string]string{"TMPDIR": tmpDir, "IS_SANDBOX": "1", "HOME": homeDir},
	}
	require.NoError(t, writeSkill(plan, tmpDir))

	// Mount point directory should be created on the "real" HOME.
	_, err := os.Stat(filepath.Join(homeDir, skillPrimaryDir))
	assert.NoError(t, err, "mount point directory should exist under HOME")

	// Bind mount should be recorded.
	require.Len(t, plan.SkillMounts, 1)
	assert.Equal(t, filepath.Join(tmpDir, skillPrimaryDir), plan.SkillMounts[0][0])
	assert.Equal(t, filepath.Join(homeDir, skillPrimaryDir), plan.SkillMounts[0][1])

	// Env var should point to the HOME-relative path, not TempDir.
	assert.Equal(t, filepath.Join(homeDir, skillPrimaryDir), plan.EnvSet[SkillDirEnvKey])

	// Skill directory should be in ROPaths for Landlock access.
	assert.Contains(t, plan.ROPaths, filepath.Join(homeDir, skillPrimaryDir))

	// Symlink at HOME/.claude/skills/curb -> HOME/.agents/skills/curb.
	homeSymlink := filepath.Join(homeDir, skillSymlinkDir)
	target, err := os.Readlink(homeSymlink)
	require.NoError(t, err, "symlink should exist under HOME")
	assert.Equal(t, "../../.agents/skills/curb", target)
}

func TestWriteSkill_HomePassthrough_NoMountNS(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := t.TempDir()
	plan := &SandboxPlan{
		ROPaths:     []string{"/usr"},
		SandboxHome: homeDir,
		UseLandlock: true,
		EnvSet:      map[string]string{"TMPDIR": tmpDir, "IS_SANDBOX": "1", "HOME": homeDir},
	}
	require.NoError(t, writeSkill(plan, tmpDir))

	// Without mount NS, env var should point to TempDir (where SKILL.md
	// actually lives), not the HOME-relative path.
	assert.Equal(t, filepath.Join(tmpDir, skillPrimaryDir), plan.EnvSet[SkillDirEnvKey])
	assert.Empty(t, plan.SkillMounts, "no bind mounts without mount NS")
	assert.Equal(t, []string{"/usr"}, plan.ROPaths, "ROPaths should be unchanged")
}
