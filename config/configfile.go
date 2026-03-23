package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/pflag"
	"github.com/upsun/curb/policy"
	"gopkg.in/yaml.v3"
)

// ConfigFile represents the sandbox-config subset of Config as loaded from a YAML file.
// Pointer types for scalars distinguish "not set" from zero value.
type ConfigFile struct {
	Profiles         []string `yaml:"profiles"`
	Domains          []string `yaml:"domains"`
	IPs              []string `yaml:"ips"`
	Read             []string `yaml:"read"`
	Write            []string `yaml:"write"`
	Exec             []string `yaml:"exec"`
	Env              []string `yaml:"env"`
	AllowUnixSockets *bool `yaml:"allow-unix-sockets"`
	UnrestrictedNet  *bool `yaml:"unrestricted-net"`
	HostLoopback     *bool `yaml:"host-loopback"`
}

// LoadConfigFile reads and decodes a YAML config file.
// Unknown keys are rejected. Domains and IPs are validated.
func LoadConfigFile(path string) (*ConfigFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var cf ConfigFile
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("config file %s: %w", path, err)
	}
	if err := cf.validate(); err != nil {
		return nil, fmt.Errorf("config file %s: %w", path, err)
	}
	return &cf, nil
}

// validate checks that domains and IPs in the config file are well-formed.
// Exclusion prefixes (!) are stripped before validation.
func (cf *ConfigFile) validate() error {
	adds, _, _ := ParseExclusions(cf.Domains)
	if len(adds) > 0 {
		if err := policy.ValidateDomains(adds); err != nil {
			return err
		}
	}
	adds, _, _ = ParseExclusions(cf.IPs)
	if len(adds) > 0 {
		if err := policy.ValidateIPs(adds); err != nil {
			return err
		}
	}
	return nil
}

// FindConfigFile walks up from the current directory looking for .curb.yaml.
// Returns the absolute path if found, or "" if not found.
func FindConfigFile() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		p := filepath.Join(dir, ".curb.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// mergeConfigLists prepends the list fields from a ConfigFile into cfg.
func mergeConfigLists(cfg *Config, cf *ConfigFile) {
	cfg.AllowedDomains = append(cf.Domains, cfg.AllowedDomains...)
	cfg.AllowedIPs = append(cf.IPs, cfg.AllowedIPs...)
	cfg.ROPaths = append(cf.Read, cfg.ROPaths...)
	cfg.RWPaths = append(cf.Write, cfg.RWPaths...)
	cfg.ExecAllow = append(cf.Exec, cfg.ExecAllow...)

	passNames, setPairs := classifyEnvArgs(cf.Env)
	cfg.EnvPassthrough = append(passNames, cfg.EnvPassthrough...)
	cfg.EnvSet = append(setPairs, cfg.EnvSet...)
}

// MergeConfigFile merges a ConfigFile into cfg.
// Lists: config-file values are prepended (so CLI/env values appear after and take precedence for exclusions).
// Scalars: config-file values apply only if the corresponding CLI flag was not explicitly set.
func MergeConfigFile(cfg *Config, cf *ConfigFile, flags *pflag.FlagSet) {
	mergeConfigLists(cfg, cf)
	applyConfigScalars(cfg, cf, flags)
}

// applyConfigScalars applies scalar and boolean fields from cf to cfg.
// Each field is applied only if the corresponding CLI flag was not
// explicitly set. Used by both MergeConfigFile and MergeProfiles.
func applyConfigScalars(cfg *Config, cf *ConfigFile, flags *pflag.FlagSet) {
	if cf.AllowUnixSockets != nil && !flags.Changed("allow-unix-sockets") {
		cfg.AllowUnixSockets = *cf.AllowUnixSockets
	}
	if cf.UnrestrictedNet != nil && !flags.Changed("unrestricted-net") {
		cfg.UnrestrictedNet = *cf.UnrestrictedNet
	}
	if cf.HostLoopback != nil && !flags.Changed("host-loopback") {
		cfg.HostLoopback = *cf.HostLoopback
	}
}
