package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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
		{"claude", false},
		{"go", false},
		{"a1", false},
		{"0start", false},
		{"", true},
		{"-leading", true},
		{"_leading_underscore", true},
		{"has_underscore", true},
		{"git_darwin", true},
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
	names := []string{"cc", "claude", "codex", "copilot", "docker", "gemini", "git", "github", "go", "make", "node", "opencode", "php", "python", "ruby", "rust", "shell", "ssh", "vibe"}
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
	assert.Equal(t, pathList{"custom-node"}, cf.Exec)
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

	_, err = MergeProfiles(cfg, []string{"node", "github"}, cmd.Flags())
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

func TestMergeProfiles_ClaudeInjectsApiKey(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	_, err = MergeProfiles(cfg, []string{"claude"}, cmd.Flags())
	require.NoError(t, err)

	assert.Contains(t, cfg.AllowedDomains, "api.anthropic.com")

	// The key is injected to api.anthropic.com from the host env var; the
	// sandbox's ANTHROPIC_API_KEY becomes a placeholder, and injection is
	// skipped when the host var is unset (OAuth).
	assert.Contains(t, cfg.InjectHeader, "ANTHROPIC_API_KEY:api.anthropic.com")
	// The real key is not passed through (it would defeat the injection).
	assert.NotContains(t, cfg.EnvPassthrough, "ANTHROPIC_API_KEY")
}

func TestMergeProfiles_Dedup(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	_, err = MergeProfiles(cfg, []string{"node", "node"}, cmd.Flags())
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

	_, err = MergeProfiles(cfg, []string{"nonexistent"}, cmd.Flags())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMergeProfiles_InvalidName(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	_, err = MergeProfiles(cfg, []string{"../bad"}, cmd.Flags())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid profile name")
}

func TestMergeProfiles_ProfilesBelowConfigFile(t *testing.T) {
	cmd := newTestCmd([]string{"--domains", "!registry.npmjs.org"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	_, err = MergeProfiles(cfg, []string{"node"}, cmd.Flags())
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
allow-unix-sockets: true
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	_, err = MergeProfiles(cfg, []string{"custom"}, cmd.Flags())
	require.NoError(t, err)

	assert.Contains(t, cfg.AllowedDomains, "example.com")
	assert.True(t, cfg.AllowUnixSockets)
}

func TestMergeProfiles_BoolScalarAgreement(t *testing.T) {
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

	_, err = MergeProfiles(cfg, []string{"a", "b"}, cmd.Flags())
	require.NoError(t, err)
	assert.True(t, cfg.AllowUnixSockets)
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

	_, err = MergeProfiles(cfg, []string{"a", "b"}, cmd.Flags())
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
allow-unix-sockets: false
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	_, err = MergeProfiles(cfg, []string{"noop"}, cmd.Flags())
	require.NoError(t, err)
	assert.False(t, cfg.AllowUnixSockets)
}

func TestMergeProfiles_ProfileScalarsApplied(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "custom.yaml"), []byte(`
domains:
  - a.com
allow-unix-sockets: true
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	// CLI does not set --allow-unix-sockets, so profile should apply.
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	_, err = MergeProfiles(cfg, []string{"custom"}, cmd.Flags())
	require.NoError(t, err)

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

	_, err = MergeProfiles(cfg, []string{"child"}, cmd.Flags())
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
	_, err = MergeProfiles(cfg, []string{"child", "base"}, cmd.Flags())
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

	_, err = MergeProfiles(cfg, []string{"a"}, cmd.Flags())
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

	_, err = MergeProfiles(cfg, []string{"a"}, cmd.Flags())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle")
	assert.Contains(t, err.Error(), "a -> b -> c -> a")
}

func TestMergeProfiles_BuiltinComposition(t *testing.T) {
	// Verify that built-in github profile composes git -> ssh.
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	_, err = MergeProfiles(cfg, []string{"github"}, cmd.Flags())
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

	_, err = MergeProfiles(cfg, []string{"go"}, cmd.Flags())
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
	assert.Equal(t, ProfileBuiltin, names["ruby"])
	assert.Equal(t, ProfileBuiltin, names["rust"])
	assert.Equal(t, ProfileBuiltin, names["git"])
	assert.Equal(t, ProfileBuiltin, names["github"])
	assert.Equal(t, ProfileBuiltin, names["docker"])
	assert.Equal(t, ProfileBuiltin, names["claude"])
	assert.Equal(t, ProfileBuiltin, names["ssh"])
	assert.Equal(t, ProfileBuiltin, names["shell"])
	assert.Equal(t, ProfileBuiltin, names["gemini"])
	assert.Equal(t, ProfileBuiltin, names["codex"])
	assert.Equal(t, ProfileBuiltin, names["opencode"])
	assert.Equal(t, ProfileBuiltin, names["vibe"])
	assert.Equal(t, ProfileBuiltin, names["copilot"])
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

func TestMatchProfile_Builtins(t *testing.T) {
	tests := []struct {
		command     string
		wantProfile string
	}{
		{"node", "node"},
		{"npm", "node"},
		{"npx", "node"},
		{"pnpm", "node"},
		{"yarn", "node"},
		{"bun", "node"},
		{"python", "python"},
		{"python3", "python"},
		{"pip", "python"},
		{"pip3", "python"},
		{"php", "php"},
		{"composer", "php"},
		{"go", "go"},
		{"ruby", "ruby"},
		{"gem", "ruby"},
		{"bundle", "ruby"},
		{"bundler", "ruby"},
		{"irb", "ruby"},
		{"rake", "ruby"},
		{"cargo", "rust"},
		{"rustc", "rust"},
		{"rustup", "rust"},
		{"git", "git"},
		{"gh", "github"},
		{"docker", "docker"},
		{"docker-compose", "docker"},
		{"claude", "claude"},
		{"gemini", "gemini"},
		{"codex", "codex"},
		{"opencode", "opencode"},
		{"vibe", "vibe"},
		{"copilot", "copilot"},
		{"ssh", "ssh"},
		{"scp", "ssh"},
		{"sftp", "ssh"},
		{"gcc", "cc"},
		{"clang", "cc"},
		{"bash", "shell"},
		{"zsh", "shell"},
		{"sh", "shell"},
		{"fish", "shell"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			name, ok, errs := MatchProfile(tt.command)
			assert.Empty(t, errs)
			assert.True(t, ok)
			assert.Equal(t, tt.wantProfile, name)
		})
	}
}

func TestMatchProfile_FullPath(t *testing.T) {
	name, ok, _ := MatchProfile("/usr/bin/python3")
	assert.True(t, ok)
	assert.Equal(t, "python", name)
}

func TestMatchProfile_NoMatch(t *testing.T) {
	_, ok, _ := MatchProfile("unknown-tool")
	assert.False(t, ok)
}

func TestMatchProfile_EmptyCommand(t *testing.T) {
	_, ok, _ := MatchProfile("")
	assert.False(t, ok)
}

func TestMatchProfile_UserProfile(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "mytool.yaml"), []byte("commands: [mytool]\ndomains:\n  - mytool.dev\n"), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	name, ok, _ := MatchProfile("mytool")
	assert.True(t, ok)
	assert.Equal(t, "mytool", name)
}

func TestMatchProfile_BrokenProfile(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "broken.yaml"), []byte("{{invalid yaml"), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, _, errs := MatchProfile("anything")
	assert.NotEmpty(t, errs)
	assert.Contains(t, errs[0].Error(), "broken")
}

func TestLoadProfile_CommandsField(t *testing.T) {
	cf, err := LoadProfile("node")
	require.NoError(t, err)
	assert.Contains(t, cf.Commands, "node")
	assert.Contains(t, cf.Commands, "npm")
	assert.Contains(t, cf.Commands, "npx")
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

// TestMergeProfiles_PlatformOverlay verifies that a "<name>_<GOOS>" overlay
// is auto-loaded and merged when "<name>" is loaded.
func TestMergeProfiles_PlatformOverlay(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "tool.yaml"), []byte(`
exec:
  - tool
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "tool_"+runtime.GOOS+".yaml"), []byte(`
exec:
  - /opt/platform-tool
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	notes, err := MergeProfiles(cfg, []string{"tool"}, cmd.Flags())
	require.NoError(t, err)
	assert.Contains(t, cfg.ExecAllow, "tool")
	assert.Contains(t, cfg.ExecAllow, "/opt/platform-tool")
	// Overlay application is reported as a debug note.
	require.Len(t, notes, 1)
	assert.Contains(t, notes[0], "tool_"+runtime.GOOS)
	assert.Contains(t, notes[0], "applied overlay")
}

// TestMergeProfiles_PlatformOverlay_WrongOSNotLoaded verifies that a non-matching
// platform overlay is not applied.
func TestMergeProfiles_PlatformOverlay_WrongOSNotLoaded(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "tool.yaml"), []byte(`
exec:
  - tool
`), 0o644))
	// Overlay for an OS that is never the current one (invert runtime.GOOS).
	otherOS := "linux"
	if runtime.GOOS == "linux" {
		otherOS = "darwin"
	}
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "tool_"+otherOS+".yaml"), []byte(`
exec:
  - /opt/should-not-load
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	notes, err := MergeProfiles(cfg, []string{"tool"}, cmd.Flags())
	require.NoError(t, err)
	assert.Contains(t, cfg.ExecAllow, "tool")
	assert.NotContains(t, cfg.ExecAllow, "/opt/should-not-load")
	assert.Empty(t, notes)
}

// TestLoadProfile_OverlayOnlyOnMatchingOS verifies that a profile whose
// only file is an "<name>_<GOOS>.yaml" overlay is loadable by its base
// name on the matching OS.
func TestLoadProfile_OverlayOnlyOnMatchingOS(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "only_"+runtime.GOOS+".yaml"), []byte(`
exec:
  - only-tool
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cf, err := LoadProfile("only")
	require.NoError(t, err)
	assert.Contains(t, cf.Exec, "only-tool")
}

// TestLoadProfile_OverlayOnlyOtherOS verifies that a profile whose only
// file is an overlay for a different OS reports a friendly error naming
// the supported OS.
func TestLoadProfile_OverlayOnlyOtherOS(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	otherOS := "linux"
	if runtime.GOOS == "linux" {
		otherOS = "darwin"
	}
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "only_"+otherOS+".yaml"), []byte(`
exec:
  - only-tool
`), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	_, err := LoadProfile("only")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only available on "+otherOS)
}

// TestLoadProfile_UnderscoreNameRejected verifies that a suffixed overlay
// name cannot be referenced directly.
func TestLoadProfile_UnderscoreNameRejected(t *testing.T) {
	_, err := LoadProfile("git_darwin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid profile name")
}

// TestMergeProfiles_OverlayNotRecursive verifies that an overlay does not
// itself attempt to load a "<name>_<os>_<os>" meta-overlay.
func TestMergeProfiles_OverlayNotRecursive(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "tool.yaml"), []byte("exec:\n  - tool\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "tool_"+runtime.GOOS+".yaml"), []byte("exec:\n  - overlay\n"), 0o644))
	// A meta-overlay must not get auto-loaded.
	metaName := "tool_" + runtime.GOOS + "_" + runtime.GOOS + ".yaml"
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, metaName), []byte("exec:\n  - meta\n"), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	_, err = MergeProfiles(cfg, []string{"tool"}, cmd.Flags())
	require.NoError(t, err)
	assert.Contains(t, cfg.ExecAllow, "tool")
	assert.Contains(t, cfg.ExecAllow, "overlay")
	assert.NotContains(t, cfg.ExecAllow, "meta")
}

// TestMergeProfiles_MakeOnDarwinPullsXcode verifies that on macOS the make
// profile composes through make_darwin -> xcode_darwin, and that $TMPDIR
// in xcode_darwin.yaml expands from the host environment.
func TestMergeProfiles_MakeOnDarwinPullsXcode(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only")
	}
	t.Setenv("TMPDIR", "/var/folders/fake/curb-test/T")

	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	_, err = MergeProfiles(cfg, []string{"make"}, cmd.Flags())
	require.NoError(t, err)

	// From make.yaml.
	assert.Contains(t, cfg.ExecAllow, "make")
	// From make_darwin.yaml.
	assert.Contains(t, cfg.ExecAllow, "/Library/Developer/CommandLineTools/usr/bin/make")
	// From xcode_darwin.yaml — $TMPDIR expanded from host env.
	assert.Contains(t, cfg.ROPaths, "/var/folders/fake/curb-test/T")
	assert.Contains(t, cfg.RWPaths, "/var/folders/fake/curb-test/T")
	assert.Contains(t, cfg.ROPaths, "/Applications/Xcode.app")
	assert.Contains(t, cfg.ROPaths, "/private/var/select")
}

// TestListProfiles_HidesOverlayFiles verifies that overlay files never
// appear as standalone entries in the listing: on the matching OS they
// fold into the base-name entry, and on other OSes they are hidden.
func TestListProfiles_HidesOverlayFiles(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "tool.yaml"), []byte("exec:\n  - tool\n"), 0o644))
	otherOS := "linux"
	if runtime.GOOS == "linux" {
		otherOS = "darwin"
	}
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "tool_"+otherOS+".yaml"), []byte("exec:\n  - other\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "tool_"+runtime.GOOS+".yaml"), []byte("exec:\n  - current\n"), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	var names []string
	for _, p := range ListProfiles() {
		names = append(names, p.Name)
	}
	assert.Contains(t, names, "tool")
	assert.NotContains(t, names, "tool_"+runtime.GOOS)
	assert.NotContains(t, names, "tool_"+otherOS)
}

// TestListProfiles_LowerSourceBaseShadowsHigherSourceOverlay verifies
// that a real base file in a lower-priority source (e.g. builtin) wins
// over an overlay-only file in a higher-priority source (e.g. user),
// matching what LoadProfile actually returns for that name.
func TestListProfiles_LowerSourceBaseShadowsHigherSourceOverlay(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	// User dir has only an overlay for a builtin profile ("python") —
	// the builtin base file should still drive the listing's Source/Path.
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "python_"+runtime.GOOS+".yaml"), []byte("exec:\n  - custom\n"), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	var found *ProfileInfo
	for _, p := range ListProfiles() {
		if p.Name == "python" {
			p := p
			found = &p
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, ProfileBuiltin, found.Source)
	assert.Empty(t, found.Path)
}

// TestListProfiles_IncludesOverlayOnlyProfile verifies that a profile
// whose only file is an overlay for the current OS is listed under its
// base name with the overlay file's path.
func TestListProfiles_IncludesOverlayOnlyProfile(t *testing.T) {
	dir := t.TempDir()
	profileDir := filepath.Join(dir, "curb", "profiles")
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	overlayPath := filepath.Join(profileDir, "only_"+runtime.GOOS+".yaml")
	require.NoError(t, os.WriteFile(overlayPath, []byte("exec:\n  - only\n"), 0o644))
	t.Setenv("XDG_CONFIG_HOME", dir)

	var found *ProfileInfo
	for _, p := range ListProfiles() {
		if p.Name == "only" {
			p := p
			found = &p
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, ProfileUser, found.Source)
	assert.Equal(t, overlayPath, found.Path)
}

// TestBuiltinProfiles_AllParse verifies that every embedded profile file
// (base and overlay) parses cleanly. Overlays are not loadable by name;
// they are read directly from the embed FS for this check.
func TestBuiltinProfiles_AllParse(t *testing.T) {
	entries, err := fs.ReadDir(builtinProfiles, "profiles")
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			data, err := builtinProfiles.ReadFile("profiles/" + e.Name())
			require.NoError(t, err)
			_, err = decodeProfile(data, e.Name())
			require.NoError(t, err)
		})
	}
}
