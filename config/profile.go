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

	"github.com/spf13/pflag"
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

// namedProfile pairs a profile name with its parsed config.
type namedProfile struct {
	name string
	cf   *ConfigFile
}

// loadProfileTree recursively loads a profile and its dependencies in
// depth-first order. stack tracks the current recursion path for cycle
// detection; loaded prevents processing a profile more than once.
func loadProfileTree(name string, stack []string, loaded map[string]bool) ([]namedProfile, error) {
	if loaded[name] {
		return nil, nil
	}
	const maxDepth = 32
	if len(stack) >= maxDepth {
		return nil, fmt.Errorf("profile nesting too deep (max %d): %s -> %s",
			maxDepth, strings.Join(stack, " -> "), name)
	}
	if slices.Contains(stack, name) {
		idx := slices.Index(stack, name)
		chain := append(slices.Clone(stack[idx:]), name)
		return nil, fmt.Errorf("profile cycle: %s", strings.Join(chain, " -> "))
	}

	cf, err := LoadProfile(name)
	if err != nil {
		return nil, err
	}

	stack = append(stack, name)
	var result []namedProfile

	for _, dep := range cf.Profiles {
		sub, subErr := loadProfileTree(dep, stack, loaded)
		if subErr != nil {
			return nil, fmt.Errorf("profile %q: %w", name, subErr)
		}
		result = append(result, sub...)
	}

	result = append(result, namedProfile{name: name, cf: cf})
	loaded[name] = true
	return result, nil
}

// MergeProfiles loads and merges named profiles into cfg, including any
// profiles they compose via the "profiles" field. List fields are appended.
// Boolean scalars are OR'd (only true is meaningful). CLI flags always take
// precedence.
func MergeProfiles(cfg *Config, names []string, flags *pflag.FlagSet) error {
	loaded := make(map[string]bool)
	var ordered []namedProfile
	for _, name := range names {
		tree, err := loadProfileTree(name, nil, loaded)
		if err != nil {
			return fmt.Errorf("--profiles: %w", err)
		}
		ordered = append(ordered, tree...)
	}

	// Merge lists and collect boolean scalars (OR'd).
	merged := new(ConfigFile)

	for _, np := range ordered {
		mergeConfigLists(cfg, np.cf)

		// Booleans: only true is meaningful (false is the default).
		orBool(&merged.AllowUnixSockets, np.cf.AllowUnixSockets)
		orBool(&merged.UnrestrictedNet, np.cf.UnrestrictedNet)
		orBool(&merged.HostLoopback, np.cf.HostLoopback)
	}

	applyConfigScalars(cfg, merged, flags)
	return nil
}

// orBool sets *dst to a pointer to true if src is non-nil and true.
func orBool(dst **bool, src *bool) {
	if src != nil && *src {
		t := true
		*dst = &t
	}
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

// MatchProfile finds the first profile whose Commands list contains the
// basename of command. Profiles are checked in alphabetical order (user
// profiles shadow builtins of the same name via ListProfiles). Returns
// the profile name and true, or "" and false if no profile matches.
// Profiles that fail to load are collected in errs.
func MatchProfile(command string) (name string, ok bool, errs []error) {
	base := filepath.Base(command)
	if base == "." || base == "/" {
		return "", false, nil
	}
	for _, p := range ListProfiles() {
		cf, err := LoadProfile(p.Name)
		if err != nil {
			errs = append(errs, fmt.Errorf("profile %q: %w", p.Name, err))
			continue
		}
		if slices.Contains(cf.Commands, base) {
			return p.Name, true, errs
		}
	}
	return "", false, errs
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
