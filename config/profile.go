package config

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed profiles/*.yaml
var builtinProfiles embed.FS

// profileNameRe validates profile names: lowercase alphanumeric with hyphens,
// must start with a letter or digit.
var profileNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// ProfileSource indicates where a profile was found.
type ProfileSource string

const (
	ProfileBuiltin ProfileSource = "builtin"
	ProfileSystem  ProfileSource = "system"
	ProfileUser    ProfileSource = "user"
)

// ProfileInfo describes an available profile.
type ProfileInfo struct {
	Name   string
	Source ProfileSource
	Path   string // Empty for builtins.
}

// ValidateProfileName checks that a profile name is safe and well-formed.
func ValidateProfileName(name string) error {
	if !profileNameRe.MatchString(name) {
		return fmt.Errorf("invalid profile name %q: must match [a-z0-9][a-z0-9-]*", name)
	}
	return nil
}

// findProfile locates a profile by name and returns its raw YAML and source.
// Search order: user dir -> system dir -> builtins. First match wins.
func findProfile(name string) ([]byte, ProfileSource, error) {
	if err := ValidateProfileName(name); err != nil {
		return nil, "", err
	}
	filename := name + ".yaml"

	// 1. User directory.
	if dir := userProfileDir(); dir != "" {
		if data, err := os.ReadFile(filepath.Join(dir, filename)); err == nil {
			return data, ProfileUser, nil
		}
	}

	// 2. System directory.
	if data, err := os.ReadFile(filepath.Join("/etc/curb/profiles", filename)); err == nil {
		return data, ProfileSystem, nil
	}

	// 3. Built-in.
	data, err := builtinProfiles.ReadFile("profiles/" + filename)
	if err != nil {
		return nil, "", fmt.Errorf("profile %q not found", name)
	}
	return data, ProfileBuiltin, nil
}

// LoadProfile loads a profile by name.
// Search order: user dir -> system dir -> builtins. First match wins.
func LoadProfile(name string) (*ConfigFile, error) {
	data, _, err := findProfile(name)
	if err != nil {
		return nil, err
	}
	return decodeProfile(data, name)
}

// MergeProfiles loads and merges named profiles into cfg.
// Only list fields are applied; scalar fields in profiles are ignored with a warning.
func MergeProfiles(cfg *Config, names []string, quiet bool) error {
	seen := make(map[string]bool)
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true

		cf, err := LoadProfile(name)
		if err != nil {
			return fmt.Errorf("--profiles: %w", err)
		}
		mergeConfigLists(cfg, cf)
		if !quiet {
			warnProfileScalars(cf, name)
		}
	}
	return nil
}

// ListProfiles returns available profiles from all sources.
// If the same name exists in multiple sources, only the highest-priority one is listed.
func ListProfiles() []ProfileInfo {
	seen := make(map[string]bool)
	var profiles []ProfileInfo

	// 1. User profiles (highest priority).
	if dir := userProfileDir(); dir != "" {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".yaml")
			if ValidateProfileName(name) != nil {
				continue
			}
			seen[name] = true
			profiles = append(profiles, ProfileInfo{
				Name:   name,
				Source: ProfileUser,
				Path:   filepath.Join(dir, e.Name()),
			})
		}
	}

	// 2. System profiles.
	entries, _ := os.ReadDir("/etc/curb/profiles")
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		if ValidateProfileName(name) != nil || seen[name] {
			continue
		}
		seen[name] = true
		profiles = append(profiles, ProfileInfo{
			Name:   name,
			Source: ProfileSystem,
			Path:   filepath.Join("/etc/curb/profiles", e.Name()),
		})
	}

	// 3. Built-in profiles (lowest priority).
	builtinEntries, _ := fs.ReadDir(builtinProfiles, "profiles")
	for _, e := range builtinEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		if seen[name] {
			continue
		}
		seen[name] = true
		profiles = append(profiles, ProfileInfo{
			Name:   name,
			Source: ProfileBuiltin,
		})
	}

	slices.SortFunc(profiles, func(a, b ProfileInfo) int {
		return strings.Compare(a.Name, b.Name)
	})
	return profiles
}

// ShowProfile returns the raw YAML content of a profile by name.
func ShowProfile(name string) ([]byte, ProfileSource, error) {
	return findProfile(name)
}

func userProfileDir() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "curb", "profiles")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "curb", "profiles")
}

func decodeProfile(data []byte, source string) (*ConfigFile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cf ConfigFile
	if err := dec.Decode(&cf); err != nil {
		return nil, fmt.Errorf("profile %s: %w", source, err)
	}
	if err := cf.validate(); err != nil {
		return nil, fmt.Errorf("profile %s: %w", source, err)
	}
	return &cf, nil
}

func warnProfileScalars(cf *ConfigFile, name string) {
	var scalars []string
	if len(cf.Profiles) > 0 {
		scalars = append(scalars, "profiles")
	}
	if cf.Proxy != nil {
		scalars = append(scalars, "proxy")
	}
	if cf.TUN != nil {
		scalars = append(scalars, "tun")
	}
	if cf.ECH != nil {
		scalars = append(scalars, "ech")
	}
	if cf.AllowHTTP != nil {
		scalars = append(scalars, "allow-http")
	}
	if cf.AllowNoSNI != nil {
		scalars = append(scalars, "allow-no-sni")
	}
	if cf.AllowUnixSockets != nil {
		scalars = append(scalars, "allow-unix-sockets")
	}
	if cf.UnrestrictedNet != nil {
		scalars = append(scalars, "unrestricted-net")
	}
	if cf.Home != nil {
		scalars = append(scalars, "home")
	}
	if len(scalars) > 0 {
		fmt.Fprintf(os.Stderr, "curb: warning: profile %q has fields (%s) which are ignored in profiles\n",
			name, strings.Join(scalars, ", "))
	}
}
