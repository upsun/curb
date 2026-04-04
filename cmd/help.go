package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/upsun/curb/clog"
)

// flagGroup defines a named group of flags for help output.
type flagGroup struct {
	Name  string
	Flags []string
}

// flagGroups defines the order and grouping of flags in help output.
var flagGroups = []flagGroup{
	{"Filesystem", []string{"read", "write"}},
	{"Network", []string{"domains", "ips", "unrestricted-net", "host-loopback", "allow-unix-sockets"}},
	{"Executables", []string{"exec"}},
	{"Environment", []string{"env"}},
	{"Profiles & Config", []string{"profiles", "auto", "config-file"}},
	{"Output", []string{"dry-run", "verbose", "debug", "quiet", "log-file"}},
}

// applyHelpTemplate sets custom usage and help templates on the root command.
func applyHelpTemplate(cmd *cobra.Command) {
	cobra.AddTemplateFuncs(template.FuncMap{
		"flagGroups":      func() []flagGroup { return flagGroups },
		"groupedFlags":    groupedFlags,
		"hasGroupedFlags": hasGroupedFlags,
		"colorHeader":     colorHeader,
		"boldFirst":       boldFirst,
	})
	cmd.SetUsageTemplate(usageTemplate)
	cmd.SetHelpTemplate(helpTemplate)
}

// boldFirst bolds the first word of a string when color is supported.
func boldFirst(s string) string {
	if !helpColor {
		return s
	}
	first, rest, ok := strings.Cut(s, " ")
	if !ok {
		return clog.ANSIBold + s + clog.ANSIReset
	}
	return clog.ANSIBold + first + clog.ANSIReset + " " + rest
}

// annotateFlags marks each flag with its group for the custom template.
func annotateFlags(f *pflag.FlagSet) {
	for _, g := range flagGroups {
		for _, name := range g.Flags {
			if fl := f.Lookup(name); fl != nil {
				fl.Annotations = map[string][]string{"group": {g.Name}}
			}
		}
	}
}

// groupedFlags returns the formatted flag lines for a given group name,
// preserving the order defined in flagGroups.
func groupedFlags(flags *pflag.FlagSet, group string) string {
	// Find the group definition to get the flag order.
	var order []string
	for _, g := range flagGroups {
		if g.Name == group {
			order = g.Flags
			break
		}
	}
	var lines []string
	for _, name := range order {
		f := flags.Lookup(name)
		if f == nil || f.Hidden {
			continue
		}
		lines = append(lines, formatFlag(f))
	}
	return strings.Join(lines, "\n")
}

// formatFlag renders a single flag line matching Cobra's default alignment.
func formatFlag(f *pflag.Flag) string {
	var short string
	if f.Shorthand != "" {
		short = fmt.Sprintf("-%s, ", f.Shorthand)
	} else {
		short = "    "
	}

	name := fmt.Sprintf("--%s", f.Name)
	typeName := flagTypeName(f)
	if typeName != "" {
		name += " " + typeName
	}

	// Pad to align descriptions at column 30 (after the 2-space indent).
	line := fmt.Sprintf("  %s%-24s  %s", short, name, f.Usage)
	return line
}

// flagTypeName returns the type label for a flag (e.g. "string", "strings").
func flagTypeName(f *pflag.Flag) string {
	typ := f.Value.Type()
	switch typ {
	case "bool":
		return ""
	case "stringSlice":
		return "strings"
	default:
		return typ
	}
}

// hasGroupedFlags reports whether any flag in the set has a group annotation.
func hasGroupedFlags(flags *pflag.FlagSet) bool {
	has := false
	flags.VisitAll(func(f *pflag.Flag) {
		if _, ok := f.Annotations["group"]; ok {
			has = true
		}
	})
	return has
}

// helpColor caches the color detection result for help output (stdout).
// Evaluated at init time; tests should set NO_COLOR=1 for predictable output.
var helpColor = clog.IsColorFd(int(os.Stdout.Fd()))

// colorHeader returns the group header, bold if color is supported.
func colorHeader(s string) string {
	if helpColor {
		return clog.ANSIBold + s + clog.ANSIReset
	}
	return s
}

// helpTemplate overrides Cobra's default to bold the first word of the Long description.
const helpTemplate = `{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces | boldFirst}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`

const usageTemplate = `{{colorHeader "Usage:"}}
  {{.UseLine}}
{{- if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]
{{- end}}
{{- $localFlags := .LocalFlags}}
{{- if hasGroupedFlags $localFlags}}
{{- range $g := flagGroups}}
{{- $content := groupedFlags $localFlags $g.Name}}
{{- if $content}}

{{colorHeader $g.Name}}:
{{$content}}
{{- end}}
{{- end}}

Modifiers (for --read, --write, --exec, --env, --domains):
  ! prefix    deny/exclude (e.g. --read '!/secret')
  !*          clear all defaults
  *           wildcard allow-all (e.g. --write '*', --env '*')
{{- else if .HasAvailableLocalFlags}}

{{colorHeader "Flags:"}}
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
{{- end}}
{{- if .HasAvailableSubCommands}}

{{colorHeader "Available Commands:"}}
{{- range .Commands}}
{{- if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding}} {{.Short}}
{{- end}}
{{- end}}
{{- end}}
{{- if .HasExample}}

{{colorHeader "Examples:"}}
{{.Example}}
{{- end}}

Use "{{.CommandPath}} [command] --help" for more information.
`
