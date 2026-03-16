package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

// ConfigFile represents the sandbox-config subset of Config as loaded from a YAML file.
// Pointer types for scalars distinguish "not set" from zero value.
type ConfigFile struct {
	Domains          []string `yaml:"domains"`
	IPs              []string `yaml:"ips"`
	Read             []string `yaml:"read"`
	Write            []string `yaml:"write"`
	Exec             []string `yaml:"exec"`
	Env              []string `yaml:"env"`
	Proxy            *string  `yaml:"proxy"`
	TUN              *string  `yaml:"tun"`
	ECH              *string  `yaml:"ech"`
	AllowHTTP        *bool    `yaml:"allow-http"`
	AllowNoSNI       *bool    `yaml:"allow-no-sni"`
	AllowUnixSockets *bool    `yaml:"allow-unix-sockets"`
	UnrestrictedNet  *bool    `yaml:"unrestricted-net"`
	Home             *string  `yaml:"home"`
}

// LoadConfigFile reads and decodes a YAML config file.
// Unknown keys are rejected.
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
	return &cf, nil
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

// MergeConfigFile merges a ConfigFile into cfg.
// Lists: config-file values are prepended (so CLI/env values appear after and take precedence for exclusions).
// Scalars: config-file values apply only if the corresponding CLI flag was not explicitly set.
func MergeConfigFile(cfg *Config, cf *ConfigFile, flags *pflag.FlagSet) {
	// Lists: prepend config-file values.
	cfg.AllowedDomains = append(cf.Domains, cfg.AllowedDomains...)
	cfg.AllowedIPs = append(cf.IPs, cfg.AllowedIPs...)
	cfg.ROPaths = append(cf.Read, cfg.ROPaths...)
	cfg.RWPaths = append(cf.Write, cfg.RWPaths...)
	cfg.ExecAllow = append(cf.Exec, cfg.ExecAllow...)

	// Env: classify and prepend.
	passNames, setPairs := classifyEnvArgs(cf.Env)
	cfg.EnvPassthrough = append(passNames, cfg.EnvPassthrough...)
	cfg.EnvSet = append(setPairs, cfg.EnvSet...)

	// Scalars: only if the CLI flag was not explicitly set.
	if cf.Proxy != nil && !flags.Changed("proxy") {
		cfg.ProxyMode = *cf.Proxy
	}
	if cf.TUN != nil && !flags.Changed("tun") {
		cfg.TUNMode = *cf.TUN
	}
	if cf.ECH != nil && !flags.Changed("ech") {
		cfg.ECHMode = *cf.ECH
	}
	if cf.AllowHTTP != nil && !flags.Changed("allow-http") {
		cfg.AllowHTTP = *cf.AllowHTTP
	}
	if cf.AllowNoSNI != nil && !flags.Changed("allow-no-sni") {
		cfg.RequireSNI = !*cf.AllowNoSNI
	}
	if cf.AllowUnixSockets != nil && !flags.Changed("allow-unix-sockets") {
		cfg.AllowUnixSockets = *cf.AllowUnixSockets
	}
	if cf.UnrestrictedNet != nil && !flags.Changed("unrestricted-net") {
		cfg.UnrestrictedNet = *cf.UnrestrictedNet
	}
	if cf.Home != nil && !flags.Changed("home") {
		home := *cf.Home
		if h, err := expandHome(home); err == nil {
			home = h
		}
		cfg.HomePath = home
	}
}
