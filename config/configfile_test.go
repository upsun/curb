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
unrestricted-net: false
`), 0o644))

	cf, err := LoadConfigFile(path)
	require.NoError(t, err)

	assert.Equal(t, []string{"pypi.org", "*.pythonhosted.org"}, cf.Domains)
	assert.Equal(t, []string{"10.0.0.0/8"}, cf.IPs)
	assert.Equal(t, pathList{"~/.cache/pip"}, cf.Read)
	assert.Equal(t, pathList{"."}, cf.Write)
	assert.Equal(t, pathList{"python3", "pip"}, cf.Exec)
	assert.Equal(t, []string{"VIRTUAL_ENV", "PIP_INDEX_URL"}, cf.Env)
	assert.Equal(t, new(false), cf.UnrestrictedNet)
}

func TestLoadConfigFile_BangPrefixPreserved(t *testing.T) {
	// yaml.v3 reads an unquoted "!something" scalar as a local tag with
	// an empty value. pathList's UnmarshalYAML recovers the literal so
	// our "!" exclusion syntax works without forcing profile authors
	// to quote every entry.
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
read:
  - /etc
  - '!/etc/shadow'
  - !/usr/local/bin
  - !~/.ssh/id_rsa
write:
  - .
  - !./.git
  - ~
`), 0o644))

	cf, err := LoadConfigFile(path)
	require.NoError(t, err)

	assert.Equal(t, pathList{
		"/etc",
		"!/etc/shadow",
		"!/usr/local/bin",
		"!~/.ssh/id_rsa",
	}, cf.Read)
	assert.Equal(t, pathList{
		".",
		"!./.git",
		"~",
	}, cf.Write)
}

func TestLoadConfigFile_EmptyPathRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
read:
  - /etc
  - ""
`), 0o644))

	_, err := LoadConfigFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read[1] is empty")
}

func TestLoadConfigFile_HomeKeyRejected(t *testing.T) {
	// The home: config field has been removed.
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
domains:
  - example.com
home: "~"
`), 0o644))

	_, err := LoadConfigFile(path)
	require.Error(t, err, "home: key should be rejected as unknown")
	assert.Contains(t, err.Error(), "home")
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
}

func TestLoadConfigFile_NotFound(t *testing.T) {
	_, err := LoadConfigFile("/nonexistent/.curb.yaml")
	require.Error(t, err)
}

func TestLoadConfigFile_InjectBearer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
inject-bearer:
  - api.github.com=@GH_TOKEN
`), 0o644))

	cf, err := LoadConfigFile(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"api.github.com=@GH_TOKEN"}, cf.InjectBearer)
}

func TestLoadConfigFile_InjectBearerInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
inject-bearer:
  - missing-source
`), 0o644))

	_, err := LoadConfigFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inject-bearer")
}

func TestLoadConfigFile_InjectBearerWildcard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
inject-bearer:
  - "*.github.com=@GH_TOKEN"
`), 0o644))

	_, err := LoadConfigFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inject-bearer")
	assert.Contains(t, err.Error(), "exact hostname")
}

func TestLoadConfigFile_InjectHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
inject-header:
  - api.anthropic.com=x-api-key=@ANTHROPIC_API_KEY
`), 0o644))

	cf, err := LoadConfigFile(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"api.anthropic.com=x-api-key=@ANTHROPIC_API_KEY"}, cf.InjectHeader)
}

func TestLoadConfigFile_InjectHeaderInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
inject-header:
  - api.anthropic.com=x-api-key
`), 0o644))

	_, err := LoadConfigFile(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inject-header")
}

func TestFindConfigFile_InCWD(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".curb.yaml")
	require.NoError(t, os.WriteFile(path, []byte("domains:\n  - a.com\n"), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	// os.Getwd() resolves symlinks (e.g. /var -> /private/var on macOS),
	// so canonicalize the expected path to match.
	canonical, err := filepath.EvalSymlinks(path)
	require.NoError(t, err)

	found := FindConfigFile()
	assert.Equal(t, canonical, found)
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

	canonical, err := filepath.EvalSymlinks(path)
	require.NoError(t, err)

	found := FindConfigFile()
	assert.Equal(t, canonical, found)
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
	cmd := newTestCmd([]string{"--domains", "cli.com", "--inject-bearer", "cli.com=@C", "--inject-header", "cli.com=x-tok=@H"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		Domains:      []string{"file.com"},
		IPs:          []string{"10.0.0.1"},
		InjectBearer: []string{"file.com=@F"},
		InjectHeader: []string{"file.com=x-api-key=@K"},
		Read:         []string{"/opt"},
		Write:        []string{"/data"},
		Exec:         []string{"python3"},
		Env:          []string{"GOPATH", "FOO=bar"},
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	assert.Equal(t, []string{"file.com", "cli.com"}, cfg.AllowedDomains)
	assert.Equal(t, []string{"10.0.0.1"}, cfg.AllowedIPs)
	assert.Equal(t, []string{"file.com=@F", "cli.com=@C"}, cfg.InjectBearer)
	assert.Equal(t, []string{"file.com=x-api-key=@K", "cli.com=x-tok=@H"}, cfg.InjectHeader)
	assert.Equal(t, []string{"/opt"}, cfg.ROPaths)
	assert.Equal(t, []string{"/data"}, cfg.RWPaths)
	assert.Equal(t, []string{"python3"}, cfg.ExecAllow)
	assert.Equal(t, []string{"GOPATH"}, cfg.EnvPassthrough)
	assert.Equal(t, []string{"FOO=bar"}, cfg.EnvSet)
}

func TestMergeConfigFile_ScalarsNotOverriddenByCLI(t *testing.T) {
	cmd := newTestCmd([]string{"--allow-unix-sockets"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		AllowUnixSockets: new(false),
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	// CLI flags take precedence.
	assert.True(t, cfg.AllowUnixSockets)
}

func TestMergeConfigFile_ScalarsAppliedWhenNoFlag(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		AllowUnixSockets: new(true),
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	assert.True(t, cfg.AllowUnixSockets)
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

func TestMergeConfigFile_ExpandEnvInPaths(t *testing.T) {
	t.Setenv("CURB_TEST_DIR", "/tmp/curb-expand-test")
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		Read:  []string{"$CURB_TEST_DIR", "${CURB_TEST_DIR}/sub"},
		Write: []string{"$CURB_TEST_DIR/out"},
		Exec:  []string{"$CURB_TEST_DIR/bin"},
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	assert.Equal(t, []string{"/tmp/curb-expand-test", "/tmp/curb-expand-test/sub"}, cfg.ROPaths)
	assert.Equal(t, []string{"/tmp/curb-expand-test/out"}, cfg.RWPaths)
	assert.Equal(t, []string{"/tmp/curb-expand-test/bin"}, cfg.ExecAllow)
}

func TestMergeConfigFile_ExpandEnvPreservesBangPrefix(t *testing.T) {
	t.Setenv("CURB_TEST_DIR", "/tmp/curb-expand-test")
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		Read: []string{"!$CURB_TEST_DIR/secret", "!*", `\!$CURB_TEST_DIR/literal-bang`},
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	assert.Equal(t, []string{
		"!/tmp/curb-expand-test/secret",
		"!*",
		`\!/tmp/curb-expand-test/literal-bang`,
	}, cfg.ROPaths)
}

func TestMergeConfigFile_ExpandEnvUnsetDropped(t *testing.T) {
	require.NoError(t, os.Unsetenv("CURB_DEFINITELY_UNSET_VAR"))
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		Read: []string{"/keep/this", "$CURB_DEFINITELY_UNSET_VAR/foo", "/also/keep"},
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	// Unset-var path is dropped; surrounding paths survive.
	assert.Equal(t, []string{"/keep/this", "/also/keep"}, cfg.ROPaths)
}

func TestMergeConfigFile_ExpandEnvPreservesDollarHome(t *testing.T) {
	// $HOME and ${HOME} are left as internal markers (not expanded to the
	// host home literal) so the plan stage can distinguish them from
	// user-written host-home paths and fire the mismatch warning correctly.
	t.Setenv("HOME", "/host/home")
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		Read: []string{
			"$HOME/.ssh",
			"${HOME}/.config",
			"/host/home/literal",
		},
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	// First two entries carry the marker (PathReferencesHome is true);
	// the literal path does not.
	require.Len(t, cfg.ROPaths, 3)
	assert.True(t, PathReferencesHome(cfg.ROPaths[0]))
	assert.True(t, PathReferencesHome(cfg.ROPaths[1]))
	assert.False(t, PathReferencesHome(cfg.ROPaths[2]))

	// The marker resolves to the host home at plan time.
	resolved := ExpandHomeRefs(cfg.ROPaths, "/host/home")
	assert.Equal(t, []string{"/host/home/.ssh", "/host/home/.config", "/host/home/literal"}, resolved)
}

func TestMergeConfigFile_ExpandEnvDollarEscape(t *testing.T) {
	t.Setenv("CURB_TEST_DIR", "/tmp/curb-expand-test")
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	cf := &ConfigFile{
		Read: []string{
			"/foo$$bar",            // literal $: "/foo$bar"
			"/foo$$$$bar",          // literal $$: "/foo$$bar"
			"$$/$CURB_TEST_DIR",    // literal $ then expansion: "$/tmp/curb-expand-test"
			"$CURB_TEST_DIR$$tail", // expansion then literal $: "/tmp/curb-expand-test$tail"
			"$${CURB_TEST_DIR}",    // escape disarms braces: "${CURB_TEST_DIR}"
			`\!$$bang`,             // bang-escape + literal $: "\!$bang"
		},
	}
	MergeConfigFile(cfg, cf, cmd.Flags())

	assert.Equal(t, []string{
		"/foo$bar",
		"/foo$$bar",
		"$//tmp/curb-expand-test",
		"/tmp/curb-expand-test$tail",
		"${CURB_TEST_DIR}",
		`\!$bang`,
	}, cfg.ROPaths)
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
