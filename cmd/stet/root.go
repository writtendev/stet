package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/writtendev/stet/internal/ui"
	"github.com/writtendev/stet/internal/version"
)

type globalFlags struct {
	json    bool
	verbose bool
}

var globals globalFlags

// newRootCmd constructs the root stet command and registers its subcommands.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "stet",
		Short: "stet is a CLI for human attestation of code merges",
		Long: `stet is a git-native CLI for cryptographic human attestation of code merges.
It records and verifies physical presence assertions over content hashes using
hardware security keys, backed by append-only git state.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:        version.Version,
	}

	root.PersistentFlags().BoolVar(&globals.json, "json", false, "Emit machine-readable JSON output")
	root.PersistentFlags().BoolVarP(&globals.verbose, "verbose", "v", false, "Enable verbose logging")

	root.SetVersionTemplate("stet version {{.Version}}\n")

	root.AddCommand(
		newSignCmd(),
		newVerifyCmd(),
		newAuditCmd(),
		newVersionCmd(),
	)

	for _, cmd := range root.Commands() {
		if cmd.Version == "" {
			cmd.Version = version.Version
		}
	}

	return root
}

// printJSON marshals v with 2-space indentation and writes it to w.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print stet version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if globals.json {
				return printJSON(out, map[string]string{
					"version": version.Version,
				})
			}
			_, err := fmt.Fprintf(out, "stet %s\n", ui.Bold.Render(version.Version))
			return err
		},
	}
}
