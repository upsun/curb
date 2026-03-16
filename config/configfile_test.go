package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
domains:
  - pypi.org
  - "*.pythonhosted.org"
ips:
  - 10.0.0.0/8
read:
  - ~/.cache/pip
write:
  - .
exec:
  - python3
  - pip
env:
  - VIRTUAL_ENV
  - PIP_INDEX_URL
home: "~"
proxy: "on"
tun: auto
ech: strip
allow-http: false
allow-no-sni: true
unrestricted-net: false
`), 0o644))

	cf, err := LoadConfigFile(path)
	require.NoError(t, err)

	assert.Equal(t, []string{"pypi.org", "*.pythonhosted.org"}, cf.Domains)
	assert.Equal(t, []string{"10.0.0.0/8"}, cf.IPs)
	assert.Equal(t, []string{"~/.cache/pip"}, cf.Read)
	assert.Equal(t, []string{"."}, cf.Write)
	assert.Equal(t, []string{"python3", "pip"}, cf.Exec)
	assert.Equal(t, []string{"VIRTUAL_ENV", "PIP_INDEX_URL"}, cf.Env)
	assert.Equal(t, new("~"), cf.Home)
	assert.Equal(t, new("on"), cf.Proxy)
	assert.Equal(t, new("auto"), cf.TUN)
	assert.Equal(t, new("strip"), cf.ECH)
	assert.Equal(t, new(false), cf.AllowHTTP)
	assert.Equal(t, new(true), cf.AllowNoSNI)
	assert.Equal(t, new(false), cf.UnrestrictedNet)
}

func TestLoadConfigFile_UnknownKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
domains:
  - example.com
unknown-key: true
`), 0o644))

	_, err := LoadConfigFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown-key")
}

func TestLoadConfigFile_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	// yaml.Decoder.Decode returns io.EOF for empty documents.
	require.NoError(t, os.WriteFile(path, []byte(""), 0o644))

	_, err := LoadConfigFile(path)
	require.Error(t, err)
}

func TestLoadConfigFile_ListsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
domains:
  - example.com
`), 0o644))

	cf, err := LoadConfigFile(path)
	require.NoError(t, err)

	assert.Equal(t, []string{"example.com"}, cf.Domains)
	assert.Nil(t, cf.IPs)
	assert.Nil(t, cf.Read)
	assert.Nil(t, cf.Proxy)
	assert.Nil(t, cf.Home)
}

func TestLoadConfigFile_NotFound(t *testing.T) {
	_, err := LoadConfigFile("/nonexistent/.curb.yaml")
	require.Error(t, err)
}

func TestFindConfigFile_InCWD(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte("domains:\n  - a.com\n"), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	found := FindConfigFile()
	assert.Equal(t, path, found)
}

func TestFindConfigFile_InParent(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "sub")
	require.NoError(t, os.Mkdir(child, 0o755))
	path := filepath.Join(parent, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte("domains:\n  - a.com\n"), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(child))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	found := FindConfigFile()
	assert.Equal(t, path, found)
}

func TestFindConfigFile_NotFound(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	found := FindConfigFile()
	assert.Empty(t, found)
}

func TestMergeConfigFile_ListsPrepend(t *testing.T) {
	cmd := newTestCmd([]string{"--domains", "cli.com"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		Domains: []string{"file.com"},
		IPs:     []string{"10.0.0.1"},
		Read:    []string{"/opt"},
		Write:   []string{"/data"},
		Exec:    []string{"python3"},
		Env:     []string{"GOPATH", "FOO=bar"},
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	assert.Equal(t, []string{"file.com", "cli.com"}, cfg.AllowedDomains)
	assert.Equal(t, []string{"10.0.0.1"}, cfg.AllowedIPs)
	assert.Equal(t, []string{"/opt"}, cfg.ROPaths)
	assert.Equal(t, []string{"/data"}, cfg.RWPaths)
	assert.Equal(t, []string{"python3"}, cfg.ExecAllow)
	assert.Equal(t, []string{"GOPATH"}, cfg.EnvPassthrough)
	assert.Equal(t, []string{"FOO=bar"}, cfg.EnvSet)
}

func TestMergeConfigFile_ScalarsNotOverriddenByCLI(t *testing.T) {
	cmd := newTestCmd([]string{"--proxy", "off", "--ech", "deny"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		Proxy: new("on"),
		ECH:   new("allow"),
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	// CLI flags take precedence.
	assert.Equal(t, "off", cfg.ProxyMode)
	assert.Equal(t, "deny", cfg.ECHMode)
}

func TestMergeConfigFile_ScalarsAppliedWhenNoFlag(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		Proxy:      new("off"),
		TUN:        new("always"),
		ECH:        new("deny"),
		AllowHTTP:  new(true),
		AllowNoSNI: new(true),
		Home:       new("/custom/home"),
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	assert.Equal(t, "off", cfg.ProxyMode)
	assert.Equal(t, "always", cfg.TUNMode)
	assert.Equal(t, "deny", cfg.ECHMode)
	assert.True(t, cfg.AllowHTTP)
	assert.False(t, cfg.RequireSNI) // allow-no-sni: true => RequireSNI: false
	assert.Equal(t, "/custom/home", cfg.HomePath)
}

func TestMergeConfigFile_HomeTildeExpansion(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{Home: new("~")}
	MergeConfigFile(cfg, cf, cmd.Flags())

	home, err := os.UserHomeDir()
	require.NoError(t, err)
	assert.Equal(t, home, cfg.HomePath)
}

func TestMergeConfigFile_CLIExclusionRemovesConfigFileEntry(t *testing.T) {
	// Config file adds pypi.org; CLI removes it with !pypi.org.
	cmd := newTestCmd([]string{"--domains", "!pypi.org"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{Domains: []string{"pypi.org", "other.com"}}
	MergeConfigFile(cfg, cf, cmd.Flags())

	// After merge, AllowedDomains = ["pypi.org", "other.com", "!pypi.org"].
	// ApplyExclusions (used later in BuildPlan) will handle the removal.
	assert.Equal(t, []string{"pypi.org", "other.com", "!pypi.org"}, cfg.AllowedDomains)
}

func TestMergeConfigFile_UnrestrictedNet(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{UnrestrictedNet: new(true)}
	MergeConfigFile(cfg, cf, cmd.Flags())

	assert.True(t, cfg.UnrestrictedNet)
}

func TestMergeConfigFile_EnvMerge(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_DOMAINS", "env.com")

	cf := &ConfigFile{Domains: []string{"file.com"}}
	MergeConfigFile(cfg, cf, cmd.Flags())
	MergeEnv(cfg, cmd)

	// Config file prepended, then env appended.
	assert.Equal(t, []string{"file.com", "env.com"}, cfg.AllowedDomains)
}
