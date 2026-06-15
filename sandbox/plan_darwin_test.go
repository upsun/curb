//go:build darwin

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/upsun/curb/config"
)

func TestIsCoveredBySubpath(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		paths []string
		want  bool
	}{
		{"exact match", "/usr", []string{"/usr", "/bin"}, true},
		{"under parent", "/usr/share/terminfo", []string{"/usr"}, true},
		{"not covered", "/Applications/Foo", []string{"/usr", "/bin"}, false},
		{"empty list", "/usr", nil, false},
		{"sibling", "/usr2", []string{"/usr"}, false},
		{"parent of entry", "/", []string{"/usr"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isCoveredBySubpath(tt.path, tt.paths))
		})
	}
}

func TestAddTerminfo_TERMINFO(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TERMINFO", dir)
	t.Setenv("TERMINFO_DIRS", "")

	plan := &SandboxPlan{Caps: &Capabilities{}}
	addTerminfo(plan)

	assert.Contains(t, plan.ROPaths, canonicalize(dir))
}

func TestAddTerminfo_TERMINFO_DIRS(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	t.Setenv("TERMINFO", "")
	t.Setenv("TERMINFO_DIRS", a+string(os.PathListSeparator)+b)

	plan := &SandboxPlan{Caps: &Capabilities{}}
	addTerminfo(plan)

	assert.Contains(t, plan.ROPaths, canonicalize(a))
	assert.Contains(t, plan.ROPaths, canonicalize(b))
}

func TestAddTerminfo_Unset(t *testing.T) {
	t.Setenv("TERMINFO", "")
	t.Setenv("TERMINFO_DIRS", "")

	plan := &SandboxPlan{Caps: &Capabilities{}}
	addTerminfo(plan)

	assert.Empty(t, plan.ROPaths)
}

func TestAddTerminfo_AlreadyCovered(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "terminfo")
	require.NoError(t, os.MkdirAll(dir, 0o755))

	parent := canonicalize(filepath.Dir(dir))
	t.Setenv("TERMINFO", dir)
	t.Setenv("TERMINFO_DIRS", "")

	plan := &SandboxPlan{
		Caps:    &Capabilities{},
		ROPaths: []string{parent},
	}
	addTerminfo(plan)

	assert.Equal(t, []string{parent}, plan.ROPaths)
}

func TestDarwinBuildPlan_InjectHeaderInactive(t *testing.T) {
	t.Setenv("DARWIN_INJECT_TOKEN", "")
	cfg := &config.Config{
		InjectHeader: []string{"DARWIN_INJECT_TOKEN=api.example.com"},
	}

	plan, err := BuildPlan(cfg, &Capabilities{}, nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.Empty(t, plan.InjectBindings)
	assert.Nil(t, plan.CA)
	assert.False(t, plan.ProxyEnabled)
}

func TestDarwinBuildPlan_InjectHeaderActiveRequiresAllowedDomain(t *testing.T) {
	t.Setenv("DARWIN_INJECT_TOKEN", "secret")
	cfg := &config.Config{
		InjectHeader: []string{"DARWIN_INJECT_TOKEN=api.example.com"},
	}

	plan, err := BuildPlan(cfg, &Capabilities{}, nil)
	require.Error(t, err)
	assert.Nil(t, plan)
	assert.Contains(t, err.Error(), `credential injection host "api.example.com" is not allowed`)
}

func TestDarwinBuildPlan_InjectHeaderActive(t *testing.T) {
	if systemCABundle() == "" {
		t.Skip("system CA bundle unavailable")
	}
	t.Setenv("DARWIN_INJECT_TOKEN", "secret")
	cfg := &config.Config{
		AllowedDomains: []string{"api.example.com"},
		InjectHeader:   []string{"DARWIN_INJECT_TOKEN=api.example.com"},
	}

	plan, err := BuildPlan(cfg, &Capabilities{}, nil)
	require.NoError(t, err)
	defer plan.Cleanup()

	assert.True(t, plan.UseSeatbelt)
	assert.True(t, plan.ProxyEnabled)
	assert.NotNil(t, plan.CA)
	assert.Contains(t, plan.InjectBindings, "api.example.com")
	assert.Equal(t, injectPlaceholder("DARWIN_INJECT_TOKEN"), plan.EnvSet["DARWIN_INJECT_TOKEN"])
}
