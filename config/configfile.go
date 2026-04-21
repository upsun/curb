package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/pflag"
	"github.com/upsun/curb/clog"
	"github.com/upsun/curb/policy"
	"gopkg.in/yaml.v3"
)

// ConfigFile represents the sandbox-config subset of Config as loaded from a YAML file.
// Pointer types for scalars distinguish "not set" from zero value.
type ConfigFile struct {
	Commands         []string `yaml:"commands"` // Basenames this profile matches (for --auto).
	Profiles         []string `yaml:"profiles"`
	Domains          []string `yaml:"domains"`
	IPs              []string `yaml:"ips"`
	Read             pathList `yaml:"read"`
	Write            pathList `yaml:"write"`
	Exec             pathList `yaml:"exec"`
	Env              []string `yaml:"env"`
	AllowUnixSockets *bool    `yaml:"allow-unix-sockets"`
	UnrestrictedNet  *bool    `yaml:"unrestricted-net"`
	HostLoopback     *bool    `yaml:"host-loopback"`
	Auto             *bool    `yaml:"auto"`
}

// pathList is a YAML list of paths. It overrides default scalar decoding
// to recover cases where yaml.v3 consumes the user's intended string
// into the tag:
//
//   - unquoted "!something" parses as a local tag with empty value
//     (Tag="!something", Value=""). The curb profiles use leading "!"
//     for exclusion, so this is a common trap.
//   - unquoted "~" or "null" parses as YAML null. Path lists want
//     the literal characters.
//
// Both cases are silently lost by the default []string decoder — entries
// end up as empty strings.
type pathList []string

func (pl *pathList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("expected a list, got kind %d", node.Kind)
	}
	out := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			return fmt.Errorf("expected string in list")
		}
		out = append(out, pathScalarLiteral(item))
	}
	*pl = out
	return nil
}

// pathScalarLiteral returns the literal string the user wrote for a
// scalar node, recovering from yaml.v3's tag/null consumption.
func pathScalarLiteral(node *yaml.Node) string {
	// Custom local tag with empty value: the literal is the tag itself.
	if node.Value == "" && strings.HasPrefix(node.Tag, "!") && !strings.HasPrefix(node.Tag, "!!") {
		return node.Tag
	}
	// Plain "~" or "null" parsed as !!null: keep the literal text.
	if node.Tag == "!!null" && node.Value != "" {
		return node.Value
	}
	return node.Value
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
	for _, pair := range [...]struct {
		field string
		list  pathList
	}{{"read", cf.Read}, {"write", cf.Write}, {"exec", cf.Exec}} {
		for i, p := range pair.list {
			if p == "" {
				return fmt.Errorf("%s[%d] is empty", pair.field, i)
			}
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
// Path fields (read, write, exec) have $VAR / ${VAR} references expanded
// from the host environment before merging; entries that expand to an
// empty string or still contain an unresolved $ are dropped with a
// warning. ~ and $HOME are resolved later at plan-build time against
// the host HOME — see ExpandHomeRefs in config/defaults.go and
// warnHostHomePathMismatch in sandbox/plan.go.
func mergeConfigLists(cfg *Config, cf *ConfigFile) {
	cfg.AllowedDomains = append(cf.Domains, cfg.AllowedDomains...)
	cfg.AllowedIPs = append(cf.IPs, cfg.AllowedIPs...)
	cfg.ROPaths = append(expandEnvPaths([]string(cf.Read), "read"), cfg.ROPaths...)
	cfg.RWPaths = append(expandEnvPaths([]string(cf.Write), "write"), cfg.RWPaths...)
	cfg.ExecAllow = append(expandEnvPaths([]string(cf.Exec), "exec"), cfg.ExecAllow...)

	passNames, setPairs := classifyEnvArgs(cf.Env)
	cfg.EnvPassthrough = append(passNames, cfg.EnvPassthrough...)
	cfg.EnvSet = append(setPairs, cfg.EnvSet...)
}

// expandEnvPaths expands $VAR and ${VAR} references in each path using the
// host environment. Exclusion prefixes (!) and literal-bang escapes (\!)
// are preserved across expansion. A literal "$" is spelled "$$" (Make
// convention). Entries are dropped — with a warning — when any referenced
// variable is unset or expansion yields an empty string. The "!*"
// clear-defaults sentinel is passed through unchanged.
//
// $HOME and ${HOME} are NOT expanded here: they are replaced with an
// internal marker (see homeRefMarker) so the plan stage can distinguish
// $HOME-origin entries from user-literal paths that happen to equal the
// host home. The marker is resolved to the host home by ExpandHomeRefs.
//
// field names the list being expanded ("read", "write", "exec") for use
// in warnings.
func expandEnvPaths(paths []string, field string) []string {
	if len(paths) == 0 {
		return nil
	}
	// SOH is used as a local placeholder to shield "$$" from os.Expand's
	// $-parsing. It's replaced back to "$" before the expanded path leaves
	// this function, so the byte never appears in the output.
	const dollarSentinel = "\x01"
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "!*" {
			out = append(out, p)
			continue
		}
		prefix, rest := "", p
		switch {
		case strings.HasPrefix(p, `\!`):
			prefix, rest = `\!`, p[2:]
		case strings.HasPrefix(p, "!"):
			prefix, rest = "!", p[1:]
		}
		shielded := strings.ReplaceAll(rest, "$$", dollarSentinel)
		var missing string
		expanded := os.Expand(shielded, func(name string) string {
			if name == "HOME" {
				return homeRefMarker
			}
			if v, ok := os.LookupEnv(name); ok {
				return v
			}
			if missing == "" {
				missing = name
			}
			return ""
		})
		expanded = strings.ReplaceAll(expanded, dollarSentinel, "$")
		if missing != "" {
			clog.Warnf("profile %s: skipping %q: variable $%s is not set in the host environment", field, p, missing)
			continue
		}
		if expanded == "" {
			clog.Warnf("profile %s: skipping %q: expands to empty string", field, p)
			continue
		}
		out = append(out, prefix+expanded)
	}
	return out
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
