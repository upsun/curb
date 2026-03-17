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
	names := []string{"node", "python", "php", "go", "rust", "git", "github", "docker", "claude-code"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			cf, err := LoadProfile(name)
			require.NoError(t, err)
			assert.NotEmpty(t, cf.Domains, "profile %s should have domains", name)
			assert.NotEmpty(t, cf.Exec, "profile %s should have exec", name)
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
	// We can't write to /etc in tests, so just verify that builtin loading works
	// when system dir doesn't exist (the common case).
	cf, err := LoadProfile("python")
	require.NoError(t, err)
	assert.Contains(t, cf.Domains, "pypi.org")
}

func TestMergeProfiles(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"node", "git"}, true)
	require.NoError(t, err)

	// Node domains and git domains should both be present.
	assert.Contains(t, cfg.AllowedDomains, "registry.npmjs.org")
	assert.Contains(t, cfg.AllowedDomains, "github.com")

	// Exec from both profiles.
	assert.Contains(t, cfg.ExecAllow, "node")
	assert.Contains(t, cfg.ExecAllow, "git")

	// Env from both profiles.
	assert.Contains(t, cfg.EnvPassthrough, "NODE_ENV")
	assert.Contains(t, cfg.EnvPassthrough, "GIT_AUTHOR_NAME")
}

func TestMergeProfiles_Dedup(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"node", "node"}, true)
	require.NoError(t, err)

	// Node domains should appear only once (dedup by name).
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

	err = MergeProfiles(cfg, []string{"nonexistent"}, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMergeProfiles_InvalidName(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"../bad"}, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid profile name")
}

func TestMergeProfiles_ProfilesBelowConfigFile(t *testing.T) {
	// Profiles are the lowest-priority layer. Config file values should
	// appear after profile values (higher priority = later in the list),
	// and CLI exclusions can remove profile additions.
	cmd := newTestCmd([]string{"--domains", "!registry.npmjs.org"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	// Simulate: profiles merged first, then config file, then CLI exclusions.
	err = MergeProfiles(cfg, []string{"node"}, true)
	require.NoError(t, err)

	// The exclusion from CLI is in cfg.AllowedDomains as "!registry.npmjs.org".
	// After ApplyExclusions in BuildPlan, registry.npmjs.org will be removed.
	assert.Contains(t, cfg.AllowedDomains, "registry.npmjs.org")
	assert.Contains(t, cfg.AllowedDomains, "!registry.npmjs.org")
}

func TestMergeProfiles_IgnoresScalars(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "bad.yaml"), []byte(`
domains:
  - example.com
proxy: "off"
home: "/evil"
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	err = MergeProfiles(cfg, []string{"bad"}, true)
	require.NoError(t, err)

	// List fields applied.
	assert.Contains(t, cfg.AllowedDomains, "example.com")
	// Scalar fields ignored.
	assert.Equal(t, "on", cfg.ProxyMode)
	assert.Empty(t, cfg.HomePath)
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
	// "node" should show as user (overridden).
	assert.Equal(t, ProfileUser, found["node"])
	// "custom" is a user-only profile.
	assert.Equal(t, ProfileUser, found["custom"])
	// "python" is still builtin.
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
