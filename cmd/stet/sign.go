package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/writtendev/stet/internal/ui"
)

func newSignCmd() *cobra.Command {
	var pushFlag bool

	cmd := &cobra.Command{
		Use:   "sign [ref]",
		Short: "Record a physical human attestation over a commit diff",
		Long: `Signs the content tree hash of the specified git ref (defaulting to HEAD)
using a physical hardware key, and records the attestation in the repository writ store.`,
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
					"command": "sign",
					"ref":     ref,
					"push":    pushFlag,
				})
			}

			if _, err := fmt.Fprintln(out, ui.Header("stet sign")); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, ui.KeyValue("Target Ref", ref)); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, ui.KeyValue("Auto-push", fmt.Sprintf("%t", pushFlag))); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, ui.Warn("stet sign write path is stubbed (pending STET-3 & STET-5 implementation)")); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&pushFlag, "push", false, "Push refs/writ/* to remote origin after signing")

	return cmd
}
