package config

import (
	"fmt"
	"os"
	"slices"
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
	ECHMode           string
	RequireSNI        bool
	AllowHTTP         bool
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
	ro, err := flags.GetStringSlice("allow-read")
	if err != nil {
		return nil, err
	}
	rw, err := flags.GetStringSlice("allow-write")
	if err != nil {
		return nil, err
	}
	hide, err := flags.GetStringSlice("hide")
	if err != nil {
		return nil, err
	}
	execAllow, err := flags.GetStringSlice("allow-exec")
	if err != nil {
		return nil, err
	}
	env, err := flags.GetStringSlice("allow-env")
	if err != nil {
		return nil, err
	}
	allowLocalhost, err := flags.GetBool("allow-localhost")
	if err != nil {
		return nil, err
	}
	echMode, err := flags.GetString("ech")
	if err != nil {
		return nil, err
	}
	switch echMode {
	case "strip", "allow", "deny":
	default:
		return nil, fmt.Errorf("--ech must be strip, allow, or deny (got %q)", echMode)
	}
	allowNoSNI, err := flags.GetBool("allow-no-sni")
	if err != nil {
		return nil, err
	}
	allowHTTP, err := flags.GetBool("allow-http")
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

	// Separate --allow-env values into passthrough names and explicit name=value pairs.
	passNames, setPairs := classifyEnvArgs(env)

	cfg := &Config{
		AllowedDomains: allow,
		ROPaths:        ro,
		RWPaths:        rw,
		HiddenPaths:    hide,
		ExecAllow:      execAllow,
		EnvPassthrough: passNames,
		EnvSet:         setPairs,
		AllowLocalhost: allowLocalhost,
		ECHMode:        echMode,
		RequireSNI:     !allowNoSNI,
		AllowHTTP:      allowHTTP,
		LogFile:        logFile,
		Verbose:        verbose,
		Quiet:          quiet,
		DryRun:         dryRun,
		HomePath:       home,
		Command:        cmd.Flags().Args(),
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
	if containsStar(passNames) {
		cfg.EnvPassthroughAll = true
		cfg.EnvPassthrough = nil
	}
	if containsStar(cfg.ROPaths) {
		cfg.ROPaths = []string{"/"}
	}

	return cfg, nil
}

// MergeEnv reads CURB_* environment variables and merges them into cfg.
// For list values, env values are appended (additive).
// For bool/string values, env values are only applied if the CLI flag was not explicitly set.
func MergeEnv(cfg *Config, cmd *cobra.Command) {
	flags := cmd.Flags()

	// List values: always additive, with wildcard detection.
	cfg.AllowedDomains = appendEnvList(cfg.AllowedDomains, "CURB_ALLOW_DOMAINS")

	roEnv := appendEnvList(nil, "CURB_ALLOW_READ")
	if containsStar(roEnv) {
		cfg.ROPaths = []string{"/"}
	} else {
		cfg.ROPaths = append(cfg.ROPaths, roEnv...)
	}

	rwEnv := appendEnvList(nil, "CURB_ALLOW_WRITE")
	if containsStar(rwEnv) {
		cfg.NoFSRestrict = true
		cfg.RWPaths = nil
	} else {
		cfg.RWPaths = append(cfg.RWPaths, rwEnv...)
	}

	cfg.HiddenPaths = appendEnvList(cfg.HiddenPaths, "CURB_HIDE")

	execEnv := appendEnvList(nil, "CURB_ALLOW_EXEC")
	if containsStar(execEnv) {
		cfg.NoExecRestrict = true
		cfg.ExecAllow = nil
	} else {
		cfg.ExecAllow = append(cfg.ExecAllow, execEnv...)
	}

	// --allow-env via CURB_ALLOW_ENV: split and classify like FromFlags.
	if val, ok := os.LookupEnv("CURB_ALLOW_ENV"); ok {
		envPass, envSet := classifyEnvArgs(splitComma(val))
		if containsStar(envPass) {
			cfg.EnvPassthroughAll = true
			cfg.EnvPassthrough = nil
		} else {
			cfg.EnvPassthrough = append(cfg.EnvPassthrough, envPass...)
			cfg.EnvSet = append(cfg.EnvSet, envSet...)
		}
	}

	// String values: env only if flag not explicitly set.
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
	mergeBoolEnv(flags, &cfg.AllowLocalhost, "allow-localhost", "CURB_ALLOW_LOCALHOST")
	mergeBoolEnv(flags, &cfg.Verbose, "verbose", "CURB_VERBOSE")
	mergeBoolEnv(flags, &cfg.Quiet, "quiet", "CURB_QUIET")

	// ECH mode: env only if flag not explicitly set.
	if !flags.Changed("ech") {
		if val, ok := os.LookupEnv("CURB_ECH"); ok {
			switch val {
			case "strip", "allow", "deny":
				cfg.ECHMode = val
			}
		}
	}
	if !flags.Changed("allow-no-sni") {
		if envBool("CURB_ALLOW_NO_SNI") {
			cfg.RequireSNI = false
		}
	}
	if !flags.Changed("allow-http") {
		if envBool("CURB_ALLOW_HTTP") {
			cfg.AllowHTTP = true
		}
	}
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

// containsStar reports whether the slice contains a literal "*" element.
func containsStar(ss []string) bool {
	return slices.Contains(ss, "*")
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
