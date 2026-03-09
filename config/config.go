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
	AllowFile         string
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
	ExactMatch        bool
	DNSUpstream       string
	LogBlocked        bool
	LogAllowed        bool
	Verbose           bool
	DryRun            bool
	HomePath          string
	Command           []string
}

// FromFlags reads flag values from the given Cobra command into a Config.
func FromFlags(cmd *cobra.Command) (*Config, error) {
	flags := cmd.Flags()

	allow, err := flags.GetStringSlice("allow")
	if err != nil {
		return nil, err
	}
	allowFile, err := flags.GetString("allow-file")
	if err != nil {
		return nil, err
	}
	ro, err := flags.GetStringSlice("ro")
	if err != nil {
		return nil, err
	}
	rw, err := flags.GetStringSlice("rw")
	if err != nil {
		return nil, err
	}
	hide, err := flags.GetStringSlice("hide")
	if err != nil {
		return nil, err
	}
	exec, err := flags.GetStringSlice("exec")
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
	exactMatch, err := flags.GetBool("exact-match")
	if err != nil {
		return nil, err
	}
	dnsUpstream, err := flags.GetString("dns-upstream")
	if err != nil {
		return nil, err
	}
	logBlocked, err := flags.GetBool("log-blocked")
	if err != nil {
		return nil, err
	}
	logAllowed, err := flags.GetBool("log-allowed")
	if err != nil {
		return nil, err
	}
	verbose, err := flags.GetBool("verbose")
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
		AllowFile:         allowFile,
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
		ExactMatch:        exactMatch,
		DNSUpstream:       dnsUpstream,
		LogBlocked:        logBlocked,
		LogAllowed:        logAllowed,
		Verbose:           verbose,
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
	cfg.AllowedDomains = appendEnvList(cfg.AllowedDomains, "CURB_ALLOW")
	cfg.ROPaths = appendEnvList(cfg.ROPaths, "CURB_RO")
	cfg.RWPaths = appendEnvList(cfg.RWPaths, "CURB_RW")
	cfg.HiddenPaths = appendEnvList(cfg.HiddenPaths, "CURB_HIDE")
	cfg.ExecAllow = appendEnvList(cfg.ExecAllow, "CURB_EXEC")

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
	if !flags.Changed("allow-file") {
		if val, ok := os.LookupEnv("CURB_ALLOW_FILE"); ok {
			cfg.AllowFile = val
		}
	}
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

	// Bool values: env only if flag not explicitly set.
	mergeBoolEnv(flags, &cfg.EnvPassthroughAll, "env-passthrough", "CURB_ENV_PASSTHROUGH")
	mergeBoolEnv(flags, &cfg.NoFSRestrict, "no-fs-restrict", "CURB_NO_FS_RESTRICT")
	mergeBoolEnv(flags, &cfg.NoExecRestrict, "no-exec-restrict", "CURB_NO_EXEC_RESTRICT")
	mergeBoolEnv(flags, &cfg.AllowLocalhost, "allow-localhost", "CURB_ALLOW_LOCALHOST")
	mergeBoolEnv(flags, &cfg.ExactMatch, "exact-match", "CURB_EXACT_MATCH")
	mergeBoolEnv(flags, &cfg.LogAllowed, "log-allowed", "CURB_LOG_ALLOWED")
	mergeBoolEnv(flags, &cfg.Verbose, "verbose", "CURB_VERBOSE")

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
