package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/upsun/curb/config"
)

// NewProfileCmd creates the "profile" subcommand with list and show.
func NewProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage sandbox profiles",
		Long:  "List and inspect reusable sandbox profiles (built-in, system, or user).",
	}
	cmd.AddCommand(newProfileListCmd())
	cmd.AddCommand(newProfileShowCmd())
	return cmd
}

func newProfileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available profiles",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			profiles := config.ListProfiles()
			if len(profiles) == 0 {
				fmt.Println("No profiles found.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintf(w, "NAME\tSOURCE\tPATH\n")
			for _, p := range profiles {
				path := p.Path
				if path == "" {
					path = "(embedded)"
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, p.Source, path)
			}
			return w.Flush()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}

func newProfileShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a profile's YAML content",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			data, source, err := config.ShowProfile(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "# source: %s\n", source)
			_, err = os.Stdout.Write(data)
			return err
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}
}
