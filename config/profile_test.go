package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateProfileName(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"node", false},
		{"claude-code", false},
		{"go", false},
		{"a1", false},
		{"0start", false},
		{"", true},
		{"-leading", true},
		{"has_underscore", true},
		{"HAS_UPPER", true},
		{"../traversal", true},
		{"path/sep", true},
		{"has space", true},
		{"has.dot", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProfileName(tt.name)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadProfile_Builtin(t *testing.T) {
	cf, err := LoadProfile("node")
	require.NoError(t, err)

	assert.Contains(t, cf.Domains, "registry.npmjs.org")
	assert.Contains(t, cf.Exec, "node")
	assert.Contains(t, cf.Env, "NODE_ENV")
}

func TestLoadProfile_AllBuiltins(t *testing.T) {
	names := []string{"node", "python", "php", "go", "rust", "git", "github", "docker", "claude-code", "ssh"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			_, err := LoadProfile(name)
			require.NoError(t, err)
		})
	}
}

func TestLoadProfile_NotFound(t *testing.T) {
	_, err := LoadProfile("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestLoadProfile_InvalidName(t *testing.T) {
	_, err := LoadProfile("../etc/passwd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid profile name")
}

func TestLoadProfile_UserOverridesBuiltin(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "node.yaml"), []byte(`
domains:
  - custom-registry.example.com
exec:
  - custom-node
`), 0o644))

	t.Setenv("XDG_CONFIG_HOME", dir)

	cf, err := LoadProfile("node")
	require.NoError(t, err)
	assert.Equal(t, []string{"custom-registry.example.com"}, cf.Domains)
	assert.Equal(t, []string{"custom-node"}, cf.Exec)
}

func TestLoadProfile_SystemOverridesBuiltin(t *testing.T) {
	cf, err := LoadProfile("python")
	require.NoError(t, err)
	assert.Contains(t, cf.Domains, "pypi.org")
}

func TestMergeProfiles(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"node", "github"}, cmd.Flags())
	require.NoError(t, err)

	// Node domains and github domains should both be present.
	assert.Contains(t, cfg.AllowedDomains, "registry.npmjs.org")
	assert.Contains(t, cfg.AllowedDomains, "github.com")

	// Exec from all profiles (ssh inherited via github -> git -> ssh).
	assert.Contains(t, cfg.ExecAllow, "node")
	assert.Contains(t, cfg.ExecAllow, "git")
	assert.Contains(t, cfg.ExecAllow, "ssh")

	// Env from all profiles.
	assert.Contains(t, cfg.EnvPassthrough, "NODE_ENV")
	assert.Contains(t, cfg.EnvPassthrough, "GIT_AUTHOR_NAME")
	assert.Contains(t, cfg.EnvPassthrough, "SSH_AUTH_SOCK")
}

func TestMergeProfiles_Dedup(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"node", "node"}, cmd.Flags())
	require.NoError(t, err)

	count := 0
	for _, d := range cfg.AllowedDomains {
		if d == "registry.npmjs.org" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestMergeProfiles_NotFound(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"nonexistent"}, cmd.Flags())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMergeProfiles_InvalidName(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"../bad"}, cmd.Flags())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid profile name")
}

func TestMergeProfiles_ProfilesBelowConfigFile(t *testing.T) {
	cmd := newTestCmd([]string{"--domains", "!registry.npmjs.org"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"node"}, cmd.Flags())
	require.NoError(t, err)

	assert.Contains(t, cfg.AllowedDomains, "registry.npmjs.org")
	assert.Contains(t, cfg.AllowedDomains, "!registry.npmjs.org")
}

func TestMergeProfiles_ScalarsApplied(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "custom.yaml"), []byte(`
domains:
  - example.com
tun: true
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"custom"}, cmd.Flags())
	require.NoError(t, err)

	assert.Contains(t, cfg.AllowedDomains, "example.com")
	assert.True(t, cfg.TUNEnabled)
}

func TestMergeProfiles_BoolScalarAgreement(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "a.yaml"), []byte(`
domains:
  - a.com
tun: true
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "b.yaml"), []byte(`
domains:
  - b.com
tun: true
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"a", "b"}, cmd.Flags())
	require.NoError(t, err)
	assert.True(t, cfg.TUNEnabled)
}

func TestMergeProfiles_BoolNoConflict(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "a.yaml"), []byte(`
domains:
  - a.com
allow-unix-sockets: true
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "b.yaml"), []byte(`
domains:
  - b.com
allow-unix-sockets: true
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"a", "b"}, cmd.Flags())
	require.NoError(t, err)
	assert.True(t, cfg.AllowUnixSockets)
}

func TestMergeProfiles_BoolFalseIgnored(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "noop.yaml"), []byte(`
domains:
  - a.com
allow-http: false
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"noop"}, cmd.Flags())
	require.NoError(t, err)
	assert.False(t, cfg.AllowHTTP)
}

func TestMergeProfiles_ProfileScalarsApplied(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "custom.yaml"), []byte(`
domains:
  - a.com
tun: true
allow-unix-sockets: true
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	// CLI does not set --tun, so profile tun: true should apply.
	// CLI does not set --allow-unix-sockets, so profile should apply.
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"custom"}, cmd.Flags())
	require.NoError(t, err)

	assert.True(t, cfg.TUNEnabled)
	assert.True(t, cfg.AllowUnixSockets)
}

func TestMergeProfiles_Composition(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "base.yaml"), []byte(`
domains:
  - base.com
exec:
  - base-tool
allow-unix-sockets: true
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "child.yaml"), []byte(`
profiles:
  - base
domains:
  - child.com
exec:
  - child-tool
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"child"}, cmd.Flags())
	require.NoError(t, err)

	// Both profiles' lists should be present.
	assert.Contains(t, cfg.AllowedDomains, "base.com")
	assert.Contains(t, cfg.AllowedDomains, "child.com")
	assert.Contains(t, cfg.ExecAllow, "base-tool")
	assert.Contains(t, cfg.ExecAllow, "child-tool")
	// Scalar from base profile should be applied.
	assert.True(t, cfg.AllowUnixSockets)
}

func TestMergeProfiles_CompositionDedup(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "base.yaml"), []byte(`
domains:
  - base.com
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "child.yaml"), []byte(`
profiles:
  - base
domains:
  - child.com
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	// "base" is included by "child" AND listed explicitly — should load once.
	err = MergeProfiles(cfg, []string{"child", "base"}, cmd.Flags())
	require.NoError(t, err)

	count := 0
	for _, d := range cfg.AllowedDomains {
		if d == "base.com" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestMergeProfiles_CycleDetection(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "a.yaml"), []byte(`
profiles:
  - b
domains:
  - a.com
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "b.yaml"), []byte(`
profiles:
  - a
domains:
  - b.com
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"a"}, cmd.Flags())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle")
}

func TestMergeProfiles_TransitiveCycle(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "a.yaml"), []byte("profiles: [b]\ndomains: [a.com]\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "b.yaml"), []byte("profiles: [c]\ndomains: [b.com]\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "c.yaml"), []byte("profiles: [a]\ndomains: [c.com]\n"), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"a"}, cmd.Flags())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle")
	assert.Contains(t, err.Error(), "a -> b -> c -> a")
}

func TestMergeProfiles_BuiltinComposition(t *testing.T) {
	// Verify that built-in github profile composes git -> ssh.
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"github"}, cmd.Flags())
	require.NoError(t, err)

	// From ssh profile (via github -> git -> ssh).
	assert.Contains(t, cfg.ExecAllow, "ssh")
	assert.Contains(t, cfg.ROPaths, "~/.ssh")
	assert.Contains(t, cfg.EnvPassthrough, "SSH_AUTH_SOCK")
	assert.True(t, cfg.AllowUnixSockets)

	// From git profile.
	assert.Contains(t, cfg.ExecAllow, "git")

	// From github profile.
	assert.Contains(t, cfg.AllowedDomains, "github.com")
	assert.Contains(t, cfg.ExecAllow, "gh")
}

func TestMergeProfiles_GoIncludesCC(t *testing.T) {
	// Verify that built-in go profile composes cc.
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"go"}, cmd.Flags())
	require.NoError(t, err)

	// From cc profile (via go -> cc).
	assert.Contains(t, cfg.ExecAllow, "gcc")
	assert.Contains(t, cfg.ExecAllow, "/usr/libexec/gcc")
	assert.Contains(t, cfg.EnvPassthrough, "CC")

	// From go profile.
	assert.Contains(t, cfg.ExecAllow, "go")
	assert.Contains(t, cfg.AllowedDomains, "proxy.golang.org")
}

func TestListProfiles_IncludesBuiltins(t *testing.T) {
	profiles := ListProfiles()
	names := make(map[string]ProfileSource)
	for _, p := range profiles {
		names[p.Name] = p.Source
	}
	assert.Equal(t, ProfileBuiltin, names["node"])
	assert.Equal(t, ProfileBuiltin, names["python"])
	assert.Equal(t, ProfileBuiltin, names["php"])
	assert.Equal(t, ProfileBuiltin, names["go"])
	assert.Equal(t, ProfileBuiltin, names["rust"])
	assert.Equal(t, ProfileBuiltin, names["git"])
	assert.Equal(t, ProfileBuiltin, names["github"])
	assert.Equal(t, ProfileBuiltin, names["docker"])
	assert.Equal(t, ProfileBuiltin, names["claude-code"])
	assert.Equal(t, ProfileBuiltin, names["ssh"])
}

func TestListProfiles_UserOverridesBuiltin(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "node.yaml"), []byte("domains:\n  - x.com\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "custom.yaml"), []byte("domains:\n  - y.com\n"), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	profiles := ListProfiles()
	found := make(map[string]ProfileSource)
	for _, p := range profiles {
		found[p.Name] = p.Source
	}
	assert.Equal(t, ProfileUser, found["node"])
	assert.Equal(t, ProfileUser, found["custom"])
	assert.Equal(t, ProfileBuiltin, found["python"])
}

func TestListProfiles_Sorted(t *testing.T) {
	profiles := ListProfiles()
	for i := 1; i < len(profiles); i++ {
		assert.LessOrEqual(t, profiles[i-1].Name, profiles[i].Name)
	}
}

func TestShowProfile_Builtin(t *testing.T) {
	data, source, err := ShowProfile("node")
	require.NoError(t, err)
	assert.Equal(t, ProfileBuiltin, source)
	assert.Contains(t, string(data), "registry.npmjs.org")
}

func TestShowProfile_NotFound(t *testing.T) {
	_, _, err := ShowProfile("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestShowProfile_UserOverridesBuiltin(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "node.yaml"), []byte("# custom\ndomains:\n  - x.com\n"), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	data, source, err := ShowProfile("node")
	require.NoError(t, err)
	assert.Equal(t, ProfileUser, source)
	assert.Contains(t, string(data), "# custom")
}
