package config

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/upsun/curb/policy"
)

// Config holds the resolved configuration after merging CLI flags, CURB_* env vars, and defaults.
type Config struct {
	AllowedDomains    []string
	ROPaths           []string
	RWPaths           []string
	ExecAllow         []string
	EnvPassthrough    []string
	EnvSet            []string
	EnvPassthroughAll bool
	AllowedIPs        []string
	InjectHeader      []string
	UnrestrictedNet   bool
	NoFSRestrict      bool
	NoExecRestrict    bool
	AllowUnixSockets  bool
	HostLoopback      bool
	LogFile           string
	Verbose           bool
	Debug             bool
	Quiet             bool
	DryRun            bool
	Auto              bool
	ConfigFilePaths   []string
	Command           []string
}

// FromFlags reads flag values from the given Cobra command into a Config.
func FromFlags(cmd *cobra.Command) (*Config, error) {
	flags := cmd.Flags()

	allow, err := flags.GetStringSlice("domains")
	if err != nil {
		return nil, err
	}
	ips, err := flags.GetStringSlice("ips")
	if err != nil {
		return nil, err
	}
	unrestrictedNet, err := flags.GetBool("unrestricted-net")
	if err != nil {
		return nil, err
	}
	ro, err := flags.GetStringSlice("read")
	if err != nil {
		return nil, err
	}
	rw, err := flags.GetStringSlice("write")
	if err != nil {
		return nil, err
	}
	execAllow, err := flags.GetStringSlice("exec")
	if err != nil {
		return nil, err
	}
	env, err := flags.GetStringSlice("env")
	if err != nil {
		return nil, err
	}
	injectHeader, err := flags.GetStringArray("inject-header")
	if err != nil {
		return nil, err
	}
	if len(allow) > 0 {
		if err := policy.ValidateDomains(allow); err != nil {
			return nil, err
		}
	}
	if len(ips) > 0 {
		if err := policy.ValidateIPs(ips); err != nil {
			return nil, err
		}
	}
	for _, e := range injectHeader {
		if _, _, err := policy.ParseInjectHeader(e); err != nil {
			return nil, fmt.Errorf("--inject-header %w", err)
		}
	}
	hostLoopback, err := flags.GetBool("host-loopback")
	if err != nil {
		return nil, err
	}
	if unrestrictedNet && (len(allow) > 0 || len(ips) > 0) {
		return nil, fmt.Errorf("--unrestricted-net cannot be combined with --domains or --ips")
	}
	if hostLoopback && unrestrictedNet {
		return nil, fmt.Errorf("--host-loopback cannot be combined with --unrestricted-net (host network is already direct)")
	}

	allowUnixSockets, err := flags.GetBool("allow-unix-sockets")
	if err != nil {
		return nil, err
	}
	logFile, err := flags.GetString("log-file")
	if err != nil {
		return nil, err
	}
	verbose, err := flags.GetBool("verbose")
	if err != nil {
		return nil, err
	}
	debug, err := flags.GetBool("debug")
	if err != nil {
		return nil, err
	}
	quiet, err := flags.GetBool("quiet")
	if err != nil {
		return nil, err
	}
	dryRun, err := flags.GetBool("dry-run")
	if err != nil {
		return nil, err
	}
	auto, err := flags.GetBool("auto")
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		AllowedDomains:   allow,
		AllowedIPs:       ips,
		InjectHeader:     injectHeader,
		UnrestrictedNet:  unrestrictedNet,
		ROPaths:          ro,
		RWPaths:          rw,
		ExecAllow:        execAllow,
		AllowUnixSockets: allowUnixSockets,
		HostLoopback:     hostLoopback,
		LogFile:          logFile,
		Verbose:          verbose,
		Debug:            debug,
		Quiet:            quiet,
		DryRun:           dryRun,
		Auto:             auto,
		Command:          cmd.Flags().Args(),
	}

	// Wildcard handling: '*' in list flags sets the corresponding escape hatch.
	if containsStar(cfg.ExecAllow) {
		cfg.NoExecRestrict = true
		cfg.ExecAllow = nil
	}
	if containsStar(cfg.RWPaths) {
		cfg.NoFSRestrict = true
		cfg.RWPaths = nil
	}
	if containsStar(cfg.ROPaths) {
		cfg.ROPaths = []string{"/"}
	}
	cfg.applyEnvArgs(env)

	return cfg, nil
}

// MergeEnv reads CURB_* environment variables and merges them into cfg.
// For list values, env values are appended (additive).
// For bool/string values, env values are only applied if the CLI flag was not explicitly set.
func MergeEnv(cfg *Config, cmd *cobra.Command) {
	flags := cmd.Flags()

	// List values: always additive, with wildcard detection.
	cfg.AllowedDomains = appendEnvList(cfg.AllowedDomains, "CURB_DOMAINS")
	cfg.AllowedIPs = appendEnvList(cfg.AllowedIPs, "CURB_IPS")
	cfg.InjectHeader = appendEnvValue(cfg.InjectHeader, "CURB_INJECT_HEADER")

	roEnv := appendEnvList(nil, "CURB_READ")
	if containsStar(roEnv) {
		cfg.ROPaths = []string{"/"}
	} else {
		cfg.ROPaths = append(cfg.ROPaths, roEnv...)
	}

	rwEnv := appendEnvList(nil, "CURB_WRITE")
	if containsStar(rwEnv) {
		cfg.NoFSRestrict = true
		cfg.RWPaths = nil
	} else {
		cfg.RWPaths = append(cfg.RWPaths, rwEnv...)
	}

	execEnv := appendEnvList(nil, "CURB_EXEC")
	if containsStar(execEnv) {
		cfg.NoExecRestrict = true
		cfg.ExecAllow = nil
	} else {
		cfg.ExecAllow = append(cfg.ExecAllow, execEnv...)
	}

	// --env via CURB_ENV: same handling as the flag.
	if val, ok := os.LookupEnv("CURB_ENV"); ok {
		cfg.applyEnvArgs(SplitComma(val))
	}

	// String values: env only if flag not explicitly set.
	if !flags.Changed("log-file") {
		if val, ok := os.LookupEnv("CURB_LOG_FILE"); ok {
			cfg.LogFile = val
		}
	}

	// Bool values: env only if flag not explicitly set.
	mergeBoolEnv(flags, &cfg.UnrestrictedNet, "unrestricted-net", "CURB_UNRESTRICTED_NET")
	mergeBoolEnv(flags, &cfg.Verbose, "verbose", "CURB_VERBOSE")
	mergeBoolEnv(flags, &cfg.Debug, "debug", "CURB_DEBUG")
	mergeBoolEnv(flags, &cfg.Quiet, "quiet", "CURB_QUIET")

	mergeBoolEnv(flags, &cfg.AllowUnixSockets, "allow-unix-sockets", "CURB_ALLOW_UNIX_SOCKETS")
	mergeBoolEnv(flags, &cfg.HostLoopback, "host-loopback", "CURB_HOST_LOOPBACK")
	mergeBoolEnv(flags, &cfg.Auto, "auto", "CURB_AUTO")
}

// classifyEnvArgs separates env args into passthrough names and explicit name=value pairs.
func classifyEnvArgs(args []string) (passNames, setPairs []string) {
	for _, v := range args {
		if strings.Contains(v, "=") {
			setPairs = append(setPairs, v)
		} else {
			passNames = append(passNames, v)
		}
	}
	return
}

// applyEnvArgs merges --env-style values (from the flag or CURB_ENV) into cfg.
// A literal "*" enables passthrough-all; explicit names are kept even then —
// --env NAME alongside '*' is still a per-variable trust decision (it opts
// NAME out of credential injection).
func (cfg *Config) applyEnvArgs(args []string) {
	passNames, setPairs := classifyEnvArgs(args)
	for _, name := range passNames {
		if name == "*" {
			cfg.EnvPassthroughAll = true
			continue
		}
		cfg.EnvPassthrough = append(cfg.EnvPassthrough, name)
	}
	cfg.EnvSet = append(cfg.EnvSet, setPairs...)
}

// EnvExplicitlyProvided reports whether the user named the variable in an
// --env argument — exact passthrough (--env NAME) or an explicit value (--env
// NAME=value). Either is a per-variable trust decision (it opts NAME out of
// credential injection); wildcard or glob passthrough is not. Explicit names
// are kept even alongside '*' (see applyEnvArgs), so the wildcard does not
// mask them.
func (cfg *Config) EnvExplicitlyProvided(name string) bool {
	for _, pair := range cfg.EnvSet {
		if k, _, _ := strings.Cut(pair, "="); k == name {
			return true
		}
	}
	adds, _, _ := ParseExclusions(cfg.EnvPassthrough)
	return slices.Contains(adds, name)
}

// containsStar reports whether the slice contains a literal "*" element.
func containsStar(ss []string) bool {
	return slices.Contains(ss, "*")
}

func appendEnvList(existing []string, envKey string) []string {
	val, ok := os.LookupEnv(envKey)
	if !ok || val == "" {
		return existing
	}
	return append(existing, SplitComma(val)...)
}

func appendEnvValue(existing []string, envKey string) []string {
	val, ok := os.LookupEnv(envKey)
	if !ok || val == "" {
		return existing
	}
	return append(existing, val)
}

// SplitComma splits a comma-separated string, trimming whitespace and dropping empties.
func SplitComma(s string) []string {
	var result []string
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func mergeBoolEnv(flags *pflag.FlagSet, target *bool, flagName, envKey string) {
	if !flags.Changed(flagName) {
		if EnvBool(envKey) {
			*target = true
		}
	}
}

// EnvBool reports whether an environment variable is set to a truthy value ("1" or "true").
func EnvBool(key string) bool {
	val := os.Getenv(key)
	return val == "1" || strings.EqualFold(val, "true")
}
