package config

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Config holds the resolved configuration after merging CLI flags, CURB_* env vars, and defaults.
type Config struct {
	AllowedDomains    []string
	ROPaths           []string
	RWPaths           []string
	HiddenPaths       []string
	ExecAllow         []string
	EnvPassthrough    []string
	EnvSet            []string
	EnvPassthroughAll bool
	NoFSRestrict      bool
	NoExecRestrict    bool
	AllowLocalhost    bool
	BlockECH          bool
	RequireSNI        bool
	AllowHTTP         bool
	DNSUpstream       string
	LogFile           string
	Verbose           bool
	Quiet             bool
	DryRun            bool
	HomePath          string
	Command           []string
}

// FromFlags reads flag values from the given Cobra command into a Config.
func FromFlags(cmd *cobra.Command) (*Config, error) {
	flags := cmd.Flags()

	allow, err := flags.GetStringSlice("allow-domains")
	if err != nil {
		return nil, err
	}
	ro, err := flags.GetStringSlice("fs-ro")
	if err != nil {
		return nil, err
	}
	rw, err := flags.GetStringSlice("fs-rw")
	if err != nil {
		return nil, err
	}
	hide, err := flags.GetStringSlice("fs-hide")
	if err != nil {
		return nil, err
	}
	exec, err := flags.GetStringSlice("allow-exec")
	if err != nil {
		return nil, err
	}
	env, err := flags.GetStringSlice("env")
	if err != nil {
		return nil, err
	}
	envPassthrough, err := flags.GetBool("env-passthrough")
	if err != nil {
		return nil, err
	}
	noFSRestrict, err := flags.GetBool("no-fs-restrict")
	if err != nil {
		return nil, err
	}
	noExecRestrict, err := flags.GetBool("no-exec-restrict")
	if err != nil {
		return nil, err
	}
	allowLocalhost, err := flags.GetBool("allow-localhost")
	if err != nil {
		return nil, err
	}
	unsafeAllowECH, err := flags.GetBool("unsafe-allow-ech")
	if err != nil {
		return nil, err
	}
	unsafeAllowNoSNI, err := flags.GetBool("unsafe-allow-no-sni")
	if err != nil {
		return nil, err
	}
	unsafeAllowHTTP, err := flags.GetBool("unsafe-allow-http")
	if err != nil {
		return nil, err
	}
	dnsUpstream, err := flags.GetString("dns-upstream")
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
	quiet, err := flags.GetBool("quiet")
	if err != nil {
		return nil, err
	}
	dryRun, err := flags.GetBool("dry-run")
	if err != nil {
		return nil, err
	}
	home, err := flags.GetString("home")
	if err != nil {
		return nil, err
	}

	// Separate --env values into passthrough names and explicit name=value pairs.
	var passNames, setPairs []string
	for _, v := range env {
		if strings.Contains(v, "=") {
			setPairs = append(setPairs, v)
		} else {
			passNames = append(passNames, v)
		}
	}

	cfg := &Config{
		AllowedDomains:    allow,
		ROPaths:           ro,
		RWPaths:           rw,
		HiddenPaths:       hide,
		ExecAllow:         exec,
		EnvPassthrough:    passNames,
		EnvSet:            setPairs,
		EnvPassthroughAll: envPassthrough,
		NoFSRestrict:      noFSRestrict,
		NoExecRestrict:    noExecRestrict,
		AllowLocalhost:    allowLocalhost,
		BlockECH:          !unsafeAllowECH,
		RequireSNI:        !unsafeAllowNoSNI,
		AllowHTTP:         unsafeAllowHTTP,
		DNSUpstream:       dnsUpstream,
		LogFile:           logFile,
		Verbose:           verbose,
		Quiet:             quiet,
		DryRun:            dryRun,
		HomePath:          home,
		Command:           cmd.Flags().Args(),
	}

	return cfg, nil
}

// MergeEnv reads CURB_* environment variables and merges them into cfg.
// For list values, env values are appended (additive).
// For bool/string values, env values are only applied if the CLI flag was not explicitly set.
func MergeEnv(cfg *Config, cmd *cobra.Command) {
	flags := cmd.Flags()

	// List values: always additive.
	cfg.AllowedDomains = appendEnvList(cfg.AllowedDomains, "CURB_ALLOW_DOMAINS")
	cfg.ROPaths = appendEnvList(cfg.ROPaths, "CURB_FS_RO")
	cfg.RWPaths = appendEnvList(cfg.RWPaths, "CURB_FS_RW")
	cfg.HiddenPaths = appendEnvList(cfg.HiddenPaths, "CURB_FS_HIDE")
	cfg.ExecAllow = appendEnvList(cfg.ExecAllow, "CURB_ALLOW_EXEC")

	// --env via CURB_ENV: split and classify like FromFlags.
	if val, ok := os.LookupEnv("CURB_ENV"); ok {
		for _, v := range splitComma(val) {
			if strings.Contains(v, "=") {
				cfg.EnvSet = append(cfg.EnvSet, v)
			} else {
				cfg.EnvPassthrough = append(cfg.EnvPassthrough, v)
			}
		}
	}

	// String values: env only if flag not explicitly set.
	if !flags.Changed("dns-upstream") {
		if val, ok := os.LookupEnv("CURB_DNS_UPSTREAM"); ok {
			cfg.DNSUpstream = val
		}
	}
	if !flags.Changed("home") {
		if val, ok := os.LookupEnv("CURB_HOME"); ok {
			cfg.HomePath = val
		}
	}
	if !flags.Changed("log-file") {
		if val, ok := os.LookupEnv("CURB_LOG_FILE"); ok {
			cfg.LogFile = val
		}
	}

	// Bool values: env only if flag not explicitly set.
	mergeBoolEnv(flags, &cfg.EnvPassthroughAll, "env-passthrough", "CURB_ENV_PASSTHROUGH")
	mergeBoolEnv(flags, &cfg.NoFSRestrict, "no-fs-restrict", "CURB_NO_FS_RESTRICT")
	mergeBoolEnv(flags, &cfg.NoExecRestrict, "no-exec-restrict", "CURB_NO_EXEC_RESTRICT")
	mergeBoolEnv(flags, &cfg.AllowLocalhost, "allow-localhost", "CURB_ALLOW_LOCALHOST")
	mergeBoolEnv(flags, &cfg.Verbose, "verbose", "CURB_VERBOSE")
	mergeBoolEnv(flags, &cfg.Quiet, "quiet", "CURB_QUIET")

	// Inverted bool flags: CURB_UNSAFE_ALLOW_ECH=1 → BlockECH=false.
	if !flags.Changed("unsafe-allow-ech") {
		if envBool("CURB_UNSAFE_ALLOW_ECH") {
			cfg.BlockECH = false
		}
	}
	if !flags.Changed("unsafe-allow-no-sni") {
		if envBool("CURB_UNSAFE_ALLOW_NO_SNI") {
			cfg.RequireSNI = false
		}
	}
	if !flags.Changed("unsafe-allow-http") {
		if envBool("CURB_UNSAFE_ALLOW_HTTP") {
			cfg.AllowHTTP = true
		}
	}
}

func appendEnvList(existing []string, envKey string) []string {
	val, ok := os.LookupEnv(envKey)
	if !ok || val == "" {
		return existing
	}
	return append(existing, splitComma(val)...)
}

func splitComma(s string) []string {
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
		if envBool(envKey) {
			*target = true
		}
	}
}

func envBool(key string) bool {
	val := os.Getenv(key)
	return val == "1" || strings.EqualFold(val, "true")
}
