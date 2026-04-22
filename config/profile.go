package config

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

//go:embed profiles/*.yaml
var builtinProfiles embed.FS

// profileNameRe validates user-facing profile names: lowercase alphanumeric
// with hyphens, must start with a letter or digit. Underscores are reserved
// for the internal platform-overlay file-naming convention (see
// platformSuffixes) and are never valid in a referenceable name.
var profileNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// platformSuffixes are the OS-specific suffixes recognized in profile *file*
// stems. A file "<name>_<suffix>.yaml" is treated as a platform overlay for
// the profile "<name>" and is only reachable on a matching runtime.GOOS.
// Overlay files are never referenced directly by name; they are auto-merged
// when "<name>" is loaded, and stand in as the base when no "<name>.yaml"
// exists (e.g. the built-in xcode profile is stored only as xcode_darwin.yaml).
var platformSuffixes = []string{"darwin", "linux"}

// splitStem parses a file stem into (base, osSuffix, hasSuffix). Stems
// without a known OS suffix return (stem, "", false).
func splitStem(stem string) (base string, osSuffix string, hasSuffix bool) {
	for _, osName := range platformSuffixes {
		if base, ok := strings.CutSuffix(stem, "_"+osName); ok {
			return base, osName, true
		}
	}
	return stem, "", false
}

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

// ValidateProfileName checks that a name is safe to use as a profile reference.
func ValidateProfileName(name string) error {
	if !profileNameRe.MatchString(name) {
		return fmt.Errorf("invalid profile name %q: must match [a-z0-9][a-z0-9-]*", name)
	}
	return nil
}

// readProfileFile reads a profile file by stem (no ".yaml" suffix, no name
// validation). Search order: user dir -> system dir -> builtins; first match
// wins. Returns an error wrapping fs.ErrNotExist when the file is absent
// from every location.
func readProfileFile(stem string) ([]byte, ProfileSource, error) {
	filename := stem + ".yaml"

	if dir := userProfileDir(); dir != "" {
		if data, err := os.ReadFile(filepath.Join(dir, filename)); err == nil {
			return data, ProfileUser, nil
		}
	}

	if data, err := os.ReadFile(filepath.Join("/etc/curb/profiles", filename)); err == nil {
		return data, ProfileSystem, nil
	}

	data, err := builtinProfiles.ReadFile("profiles/" + filename)
	if err != nil {
		return nil, "", fmt.Errorf("profile file %q not found: %w", filename, fs.ErrNotExist)
	}
	return data, ProfileBuiltin, nil
}

// findProfile resolves a user-facing profile name to YAML data. Validates
// the name, then in order: the base file "<name>.yaml"; the current-OS
// overlay "<name>_<GOOS>.yaml" (standing in as the base if none exists).
// fromOverlay is true iff the overlay was returned as the base. If the
// profile only exists as an overlay for a different OS, returns a friendly
// error identifying that OS. Otherwise returns an error wrapping
// fs.ErrNotExist.
func findProfile(name string) ([]byte, ProfileSource, bool, error) {
	if err := ValidateProfileName(name); err != nil {
		return nil, "", false, err
	}

	if data, src, err := readProfileFile(name); err == nil {
		return data, src, false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, "", false, err
	}

	if data, src, err := readProfileFile(name + "_" + runtime.GOOS); err == nil {
		return data, src, true, nil
	}

	for _, osName := range platformSuffixes {
		if osName == runtime.GOOS {
			continue
		}
		if _, _, err := readProfileFile(name + "_" + osName); err == nil {
			return nil, "", false, fmt.Errorf("profile %q is only available on %s (current OS: %s)", name, osName, runtime.GOOS)
		}
	}
	return nil, "", false, fmt.Errorf("profile %q not found: %w", name, fs.ErrNotExist)
}

// LoadProfile loads a profile by name. An overlay-only profile (no base
// file, just "<name>_<GOOS>.yaml") is returned as-is on the matching OS.
func LoadProfile(name string) (*ConfigFile, error) {
	data, _, fromOverlay, err := findProfile(name)
	if err != nil {
		return nil, err
	}
	return decodeProfile(data, decodeLabel(name, fromOverlay))
}

// decodeLabel returns the string used in parse-error messages: the actual
// filename (without extension) so failures in overlay-only profiles point
// at the overlay file rather than the user-facing base name.
func decodeLabel(name string, fromOverlay bool) string {
	if fromOverlay {
		return name + "_" + runtime.GOOS
	}
	return name
}

// namedProfile pairs a profile name with its parsed config.
type namedProfile struct {
	name string
	cf   *ConfigFile
}

// loadProfileTree recursively loads a profile and its dependencies in
// depth-first order. stack tracks the current recursion path for cycle
// detection; loaded prevents processing a profile more than once.
// The second return value carries debug messages about overlay application;
// callers concatenate and forward them to the logger.
func loadProfileTree(name string, stack []string, loaded map[string]bool) ([]namedProfile, []string, error) {
	if loaded[name] {
		return nil, nil, nil
	}
	const maxDepth = 32
	if len(stack) >= maxDepth {
		return nil, nil, fmt.Errorf("profile nesting too deep (max %d): %s -> %s",
			maxDepth, strings.Join(stack, " -> "), name)
	}
	if slices.Contains(stack, name) {
		idx := slices.Index(stack, name)
		chain := append(slices.Clone(stack[idx:]), name)
		return nil, nil, fmt.Errorf("profile cycle: %s", strings.Join(chain, " -> "))
	}

	data, _, fromOverlay, err := findProfile(name)
	if err != nil {
		return nil, nil, err
	}
	cf, err := decodeProfile(data, decodeLabel(name, fromOverlay))
	if err != nil {
		return nil, nil, err
	}

	stack = append(stack, name)
	var result []namedProfile
	var notes []string

	for _, dep := range cf.Profiles {
		sub, subNotes, subErr := loadProfileTree(dep, stack, loaded)
		if subErr != nil {
			return nil, nil, fmt.Errorf("profile %q: %w", name, subErr)
		}
		result = append(result, sub...)
		notes = append(notes, subNotes...)
	}

	// Merge the platform overlay unless findProfile already returned it
	// as the base (no distinct <name>.yaml exists).
	if !fromOverlay {
		overlayStem := name + "_" + runtime.GOOS
		switch overlayData, _, err := readProfileFile(overlayStem); {
		case err == nil:
			overlayCf, decErr := decodeProfile(overlayData, overlayStem)
			if decErr != nil {
				return nil, nil, fmt.Errorf("profile %q: overlay %q: %w", name, overlayStem, decErr)
			}
			for _, dep := range overlayCf.Profiles {
				sub, subNotes, subErr := loadProfileTree(dep, stack, loaded)
				if subErr != nil {
					return nil, nil, fmt.Errorf("profile %q overlay: %w", name, subErr)
				}
				result = append(result, sub...)
				notes = append(notes, subNotes...)
			}
			result = append(result, namedProfile{name: overlayStem, cf: overlayCf})
			notes = append(notes, fmt.Sprintf("profile %q: applied overlay %q", name, overlayStem))
		case errors.Is(err, fs.ErrNotExist):
			// No overlay for this platform.
		default:
			return nil, nil, fmt.Errorf("profile %q: overlay %q: %w", name, overlayStem, err)
		}
	}

	result = append(result, namedProfile{name: name, cf: cf})
	loaded[name] = true
	return result, notes, nil
}

// MergeProfiles loads and merges named profiles into cfg, including any
// profiles they compose via the "profiles" field. List fields are appended.
// Boolean scalars are OR'd (only true is meaningful). CLI flags always take
// precedence. The returned notes are debug-level messages about overlay
// application; callers typically forward them to logger.Debug after logger
// construction.
func MergeProfiles(cfg *Config, names []string, flags *pflag.FlagSet) ([]string, error) {
	loaded := make(map[string]bool)
	var ordered []namedProfile
	var notes []string
	for _, name := range names {
		tree, treeNotes, err := loadProfileTree(name, nil, loaded)
		if err != nil {
			return notes, fmt.Errorf("--profiles: %w", err)
		}
		ordered = append(ordered, tree...)
		notes = append(notes, treeNotes...)
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
	return notes, nil
}

// orBool sets *dst to a pointer to true if src is non-nil and true.
func orBool(dst **bool, src *bool) {
	if src != nil && *src {
		t := true
		*dst = &t
	}
}

// ListProfiles returns available profiles from all sources, deduplicated by
// name with user > system > builtin precedence. Overlay files
// ("<name>_<OS>.yaml") never appear as standalone entries: on the matching
// OS they contribute to the base-name entry; on other OSes they are hidden.
func ListProfiles() []ProfileInfo {
	type source struct {
		kind    ProfileSource
		dir     string // empty for builtins
		entries []fs.DirEntry
	}
	var sources []source
	if dir := userProfileDir(); dir != "" {
		entries, _ := os.ReadDir(dir)
		sources = append(sources, source{ProfileUser, dir, entries})
	}
	sysDir := "/etc/curb/profiles"
	sysEntries, _ := os.ReadDir(sysDir)
	sources = append(sources, source{ProfileSystem, sysDir, sysEntries})
	builtinEntries, _ := fs.ReadDir(builtinProfiles, "profiles")
	sources = append(sources, source{ProfileBuiltin, "", builtinEntries})

	seen := make(map[string]bool)
	var profiles []ProfileInfo

	// Pass order: base files across all sources in precedence order, then
	// overlay-only files across all sources. A real base in a lower-priority
	// source must shadow an overlay-only file in a higher-priority source,
	// since that is what LoadProfile will return.
	for _, overlayPass := range []bool{false, true} {
		for _, src := range sources {
			for _, e := range src.entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
					continue
				}
				stem := strings.TrimSuffix(e.Name(), ".yaml")
				base, osName, hasSuffix := splitStem(stem)
				if hasSuffix && osName != runtime.GOOS {
					continue
				}
				if hasSuffix != overlayPass {
					continue
				}
				if ValidateProfileName(base) != nil || seen[base] {
					continue
				}
				seen[base] = true
				info := ProfileInfo{Name: base, Source: src.kind}
				if src.dir != "" {
					info.Path = filepath.Join(src.dir, e.Name())
				}
				profiles = append(profiles, info)
			}
		}
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

// ShowProfile returns the raw YAML content of a profile by name. On the
// current OS, an overlay-only profile returns its overlay contents. A
// profile that only exists for another OS returns a descriptive error.
func ShowProfile(name string) ([]byte, ProfileSource, error) {
	data, src, _, err := findProfile(name)
	return data, src, err
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
