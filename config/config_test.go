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
	f.StringSlice("domains", nil, "")
	f.StringSlice("read", nil, "")
	f.StringSlice("write", nil, "")
	f.StringSlice("exec", nil, "")
	f.StringSlice("env", nil, "")
	f.StringSlice("ips", nil, "")
	f.Bool("unrestricted-net", false, "")
	f.Bool("allow-http", false, "")
	f.Bool("allow-unix-sockets", false, "")
	f.String("log-file", "", "")
	f.BoolP("verbose", "v", false, "")
	f.Bool("debug", false, "")
	f.BoolP("quiet", "q", false, "")
	f.Bool("dry-run", false, "")
	f.String("proxy", "on", "")
	f.String("tun", "auto", "")
	f.StringSliceP("config-file", "c", nil, "")

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
	assert.False(t, cfg.AllowHTTP, "AllowHTTP defaults to false")
	assert.Empty(t, cfg.LogFile)
	assert.False(t, cfg.Verbose)
	assert.False(t, cfg.DryRun)
}

func TestFromFlags_AllFlags(t *testing.T) {
	cmd := newTestCmd([]string{
		"--domains", "a.com,b.com",
		"--read", "/opt",
		"--write", "/data",
		"--exec", "rg",
		"--env", "GOPATH",
		"--env", "FOO=bar",
		"--allow-http",
		"--log-file", "/tmp/curb.log",
		"-v",
		"--dry-run",
	})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	assert.Equal(t, []string{"a.com", "b.com"}, cfg.AllowedDomains)
	assert.Equal(t, []string{"/opt"}, cfg.ROPaths)
	assert.Equal(t, []string{"/data"}, cfg.RWPaths)
	assert.Equal(t, []string{"rg"}, cfg.ExecAllow)
	assert.Equal(t, []string{"GOPATH"}, cfg.EnvPassthrough)
	assert.Equal(t, []string{"FOO=bar"}, cfg.EnvSet)
	assert.False(t, cfg.EnvPassthroughAll)
	assert.False(t, cfg.NoFSRestrict)
	assert.False(t, cfg.NoExecRestrict)
	assert.True(t, cfg.AllowHTTP, "--allow-http sets AllowHTTP")
	assert.Equal(t, "/tmp/curb.log", cfg.LogFile)
	assert.True(t, cfg.Verbose)
	assert.True(t, cfg.DryRun)
}

func TestFromFlags_WildcardExec(t *testing.T) {
	cmd := newTestCmd([]string{"--exec", "*"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)
	assert.True(t, cfg.NoExecRestrict)
	assert.Empty(t, cfg.ExecAllow)
}

func TestFromFlags_WildcardWrite(t *testing.T) {
	cmd := newTestCmd([]string{"--write", "*"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)
	assert.True(t, cfg.NoFSRestrict)
	assert.Empty(t, cfg.RWPaths)
}

func TestFromFlags_WildcardEnv(t *testing.T) {
	cmd := newTestCmd([]string{"--env", "*"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)
	assert.True(t, cfg.EnvPassthroughAll)
	assert.Empty(t, cfg.EnvPassthrough)
}

func TestFromFlags_WildcardRead(t *testing.T) {
	cmd := newTestCmd([]string{"--read", "*"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)
	assert.Equal(t, []string{"/"}, cfg.ROPaths)
}

func TestMergeEnv_ListsAdditive(t *testing.T) {
	cmd := newTestCmd([]string{"--domains", "b.com"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_DOMAINS", "a.com")
	MergeEnv(cfg, cmd)

	assert.Equal(t, []string{"b.com", "a.com"}, cfg.AllowedDomains)
}

func TestMergeEnv_CommaSeparatedList(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_EXEC", "rg, jq, fd")
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

func TestMergeEnv_AllowHTTPFromEnv(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ALLOW_HTTP", "true")
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.AllowHTTP)
}

func TestMergeEnv_EnvVarClassification(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ENV", "GOPATH,FOO=bar")
	MergeEnv(cfg, cmd)

	assert.Equal(t, []string{"GOPATH"}, cfg.EnvPassthrough)
	assert.Equal(t, []string{"FOO=bar"}, cfg.EnvSet)
}

func TestMergeEnv_WildcardExec(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_EXEC", "*")
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.NoExecRestrict)
	assert.Empty(t, cfg.ExecAllow)
}

func TestMergeEnv_WildcardWrite(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_WRITE", "*")
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.NoFSRestrict)
	assert.Empty(t, cfg.RWPaths)
}

func TestMergeEnv_WildcardEnv(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ENV", "*")
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.EnvPassthroughAll)
	assert.Empty(t, cfg.EnvPassthrough)
}

func TestMergeEnv_WildcardEnvValueNotPassthrough(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	// FOO=* is a set-pair, not a wildcard passthrough.
	t.Setenv("CURB_ENV", "FOO=*")
	MergeEnv(cfg, cmd)

	assert.False(t, cfg.EnvPassthroughAll, "FOO=* should not trigger passthrough-all")
	assert.Equal(t, []string{"FOO=*"}, cfg.EnvSet)
}

func TestFromFlags_WildcardEnvValueNotPassthrough(t *testing.T) {
	cmd := newTestCmd([]string{"--env", "FOO=*"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	assert.False(t, cfg.EnvPassthroughAll, "FOO=* should not trigger passthrough-all")
	assert.Equal(t, []string{"FOO=*"}, cfg.EnvSet)
}

func TestMergeEnv_WildcardRead(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_READ", "*")
	MergeEnv(cfg, cmd)

	assert.Equal(t, []string{"/"}, cfg.ROPaths)
}

func TestMergeEnv_LogFileNotOverriddenWhenFlagSet(t *testing.T) {
	cmd := newTestCmd([]string{"--log-file", "/cli/log"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_LOG_FILE", "/env/log")
	MergeEnv(cfg, cmd)

	assert.Equal(t, "/cli/log", cfg.LogFile)
}

func TestMergeEnv_LogFileFromEnv(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_LOG_FILE", "/env/log")
	MergeEnv(cfg, cmd)

	assert.Equal(t, "/env/log", cfg.LogFile)
}

func TestMergeEnv_AllowHTTP(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_ALLOW_HTTP", "true")
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.AllowHTTP)
}

func TestFromFlags_IPsAndUnrestrictedNet(t *testing.T) {
	cmd := newTestCmd([]string{"--ips", "10.0.0.1,192.168.0.0/16"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1", "192.168.0.0/16"}, cfg.AllowedIPs)
	assert.False(t, cfg.UnrestrictedNet)
}

func TestFromFlags_UnrestrictedNet(t *testing.T) {
	cmd := newTestCmd([]string{"--unrestricted-net"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)
	assert.True(t, cfg.UnrestrictedNet)
}

func TestFromFlags_UnrestrictedNetWithDomains(t *testing.T) {
	cmd := newTestCmd([]string{"--unrestricted-net", "--domains", "example.com"})
	_, err := FromFlags(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--unrestricted-net cannot be combined")
}

func TestFromFlags_UnrestrictedNetWithIPs(t *testing.T) {
	cmd := newTestCmd([]string{"--unrestricted-net", "--ips", "10.0.0.1"})
	_, err := FromFlags(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--unrestricted-net cannot be combined")
}

func TestFromFlags_InvalidDomain(t *testing.T) {
	cmd := newTestCmd([]string{"--domains", "http://example.com"})
	_, err := FromFlags(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "looks like a URL")
}

func TestFromFlags_InvalidIP(t *testing.T) {
	cmd := newTestCmd([]string{"--ips", "not-an-ip"})
	_, err := FromFlags(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid IP")
}

func TestFromFlags_DomainIsIP(t *testing.T) {
	cmd := newTestCmd([]string{"--domains", "192.168.1.1"})
	_, err := FromFlags(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "use --ips instead")
}

func TestMergeEnv_IPsAdditive(t *testing.T) {
	cmd := newTestCmd([]string{"--ips", "10.0.0.1"})
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_IPS", "10.0.0.2")
	MergeEnv(cfg, cmd)

	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, cfg.AllowedIPs)
}

func TestMergeEnv_UnrestrictedNet(t *testing.T) {
	cmd := newTestCmd(nil)
	cfg, err := FromFlags(cmd)
	require.NoError(t, err)

	t.Setenv("CURB_UNRESTRICTED_NET", "1")
	MergeEnv(cfg, cmd)

	assert.True(t, cfg.UnrestrictedNet)
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
			assert.Equal(t, tt.want, SplitComma(tt.in))
		})
	}
}
