package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/writtendev/stet/internal/ui"
)

func newVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify [ref]",
		Short: "Verify hardware attestations for a commit",
		Long: `Traverses the local writ store to verify cryptographic signatures and physical
human attestations for the specified commit or ref (defaulting to HEAD).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := "HEAD"
			if len(args) > 0 {
				ref = args[0]
			}

			out := cmd.OutOrStdout()

			if globals.json {
				return printJSON(out, map[string]any{
					"status":  "stubbed",
					"command": "verify",
					"ref":     ref,
				})
			}

			if _, err := fmt.Fprintln(out, ui.Header("stet verify")); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, ui.KeyValue("Target Ref", ref)); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, ui.Warn("stet verify read path is stubbed (pending STET-4 implementation)")); err != nil {
				return err
			}
			return nil
		},
	}
}
