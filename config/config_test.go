package config

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestCmd creates a root command with all flags registered, for testing.
func newTestCmd(args []string) *cobra.Command {
	cmd := &cobra.Command{
		Use:  "curb",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return nil },
	}
	f := cmd.Flags()
	f.StringSlice("allow-domains", nil, "")
	f.StringSlice("allow-read", nil, "")
	f.StringSlice("allow-write", nil, "")
	f.StringSlice("hide", nil, "")
	f.StringSlice("allow-exec", nil, "")
	f.StringSlice("allow-env", nil, "")
	f.Bool("allow-localhost", false, "")
	f.Bool("allow-ech", false, "")
	f.Bool("allow-no-sni", false, "")
	f.Bool("allow-http", false, "")
	f.String("log-file", "", "")
	f.BoolP("verbose", "v", false, "")
	f.BoolP("quiet", "q", false, "")
	f.Bool("dry-run", false, "")
	f.String("home", "", "")

	cmd.SetArgs(args)
	_ = cmd.Execute()
	return cmd
}

func TestFromFlags_Defaults(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	assert.Empty(t, cfg.AllowedDomains)
	assert.Empty(t, cfg.ROPaths)
	assert.Empty(t, cfg.RWPaths)
	assert.False(t, cfg.EnvPassthroughAll)
	assert.False(t, cfg.NoFSRestrict)
	assert.False(t, cfg.AllowLocalhost)
	assert.True(t, cfg.BlockECH, "BlockECH defaults to true")
	assert.True(t, cfg.RequireSNI, "RequireSNI defaults to true")
	assert.False(t, cfg.AllowHTTP, "AllowHTTP defaults to false")
	assert.Empty(t, cfg.LogFile)
	assert.False(t, cfg.Verbose)
	assert.False(t, cfg.DryRun)
}

func TestFromFlags_AllFlags(t *testing.T) {
	cmd := newTestCmd([]string{
		"--allow-domains", "a.com,b.com",
		"--allow-read", "/opt",
		"--allow-write", "/data",
		"--hide", "/secret",
		"--allow-exec", "rg",
		"--allow-env", "GOPATH",
		"--allow-env", "FOO=bar",
		"--allow-localhost",
		"--allow-ech",
		"--allow-no-sni",
		"--allow-http",
		"--log-file", "/tmp/curb.log",
		"-v",
		"--dry-run",
		"--home", "/custom/home",
	})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	assert.Equal(t, []string{"a.com", "b.com"}, cfg.AllowedDomains)
	assert.Equal(t, []string{"/opt"}, cfg.ROPaths)
	assert.Equal(t, []string{"/data"}, cfg.RWPaths)
	assert.Equal(t, []string{"/secret"}, cfg.HiddenPaths)
	assert.Equal(t, []string{"rg"}, cfg.ExecAllow)
	assert.Equal(t, []string{"GOPATH"}, cfg.EnvPassthrough)
	assert.Equal(t, []string{"FOO=bar"}, cfg.EnvSet)
	assert.False(t, cfg.EnvPassthroughAll)
	assert.False(t, cfg.NoFSRestrict)
	assert.False(t, cfg.NoExecRestrict)
	assert.True(t, cfg.AllowLocalhost)
	assert.False(t, cfg.BlockECH, "--allow-ech inverts BlockECH")
	assert.False(t, cfg.RequireSNI, "--allow-no-sni inverts RequireSNI")
	assert.True(t, cfg.AllowHTTP, "--allow-http sets AllowHTTP")
	assert.Equal(t, "/tmp/curb.log", cfg.LogFile)
	assert.True(t, cfg.Verbose)
	assert.True(t, cfg.DryRun)
	assert.Equal(t, "/custom/home", cfg.HomePath)
}

func TestFromFlags_WildcardExec(t *testing.T) {
	cmd := newTestCmd([]string{"--allow-exec", "*"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)
	assert.True(t, cfg.NoExecRestrict)
	assert.Empty(t, cfg.ExecAllow)
}

func TestFromFlags_WildcardWrite(t *testing.T) {
	cmd := newTestCmd([]string{"--allow-write", "*"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)
	assert.True(t, cfg.NoFSRestrict)
	assert.Empty(t, cfg.RWPaths)
}

func TestFromFlags_WildcardEnv(t *testing.T) {
	cmd := newTestCmd([]string{"--allow-env", "*"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)
	assert.True(t, cfg.EnvPassthroughAll)
	assert.Empty(t, cfg.EnvPassthrough)
}

func TestFromFlags_WildcardRead(t *testing.T) {
	cmd := newTestCmd([]string{"--allow-read", "*"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)
	assert.Equal(t, []string{"/"}, cfg.ROPaths)
}

func TestMergeEnv_ListsAdditive(t *testing.T) {
	cmd := newTestCmd([]string{"--allow-domains", "b.com"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ALLOW_DOMAINS", "a.com")
	MergeEnv(cfg, cmd)

	assert.Equal(t, []string{"b.com", "a.com"}, cfg.AllowedDomains)
}

func TestMergeEnv_CommaSeparatedList(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ALLOW_EXEC", "rg, jq, fd")
	MergeEnv(cfg, cmd)

	assert.Equal(t, []string{"rg", "jq", "fd"}, cfg.ExecAllow)
}

func TestMergeEnv_CLIPrecedenceForBools(t *testing.T) {
	cmd := newTestCmd([]string{"--verbose"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	// Even if env says false, CLI should win (the flag was explicitly set).
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.Verbose)
}

func TestMergeEnv_EnvOnlyBool(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_VERBOSE", "true")
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.Verbose)
}

func TestMergeEnv_InvertedBools(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ALLOW_ECH", "1")
	t.Setenv("CURB_ALLOW_HTTP", "true")
	MergeEnv(cfg, cmd)

	assert.False(t, cfg.BlockECH)
	assert.True(t, cfg.AllowHTTP)
}

func TestMergeEnv_EnvVarClassification(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ALLOW_ENV", "GOPATH,FOO=bar")
	MergeEnv(cfg, cmd)

	assert.Equal(t, []string{"GOPATH"}, cfg.EnvPassthrough)
	assert.Equal(t, []string{"FOO=bar"}, cfg.EnvSet)
}

func TestMergeEnv_WildcardExec(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ALLOW_EXEC", "*")
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.NoExecRestrict)
	assert.Empty(t, cfg.ExecAllow)
}

func TestMergeEnv_WildcardWrite(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ALLOW_WRITE", "*")
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.NoFSRestrict)
	assert.Empty(t, cfg.RWPaths)
}

func TestMergeEnv_WildcardEnv(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ALLOW_ENV", "*")
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.EnvPassthroughAll)
	assert.Empty(t, cfg.EnvPassthrough)
}

func TestSplitComma(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "a.com", []string{"a.com"}},
		{"multiple", "a.com, b.com, c.com", []string{"a.com", "b.com", "c.com"}},
		{"trailing comma", "a.com,", []string{"a.com"}},
		{"whitespace only", "  ,  ,  ", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, splitComma(tt.in))
		})
	}
}
