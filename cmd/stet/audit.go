package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/writtendev/stet/internal/ui"
)

func newAuditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "audit",
		Short: "Generate a zero-config repository human review audit",
		Long: `Audits repository commit history and merge patterns to assess human approval
coverage, latency, self-merges, and bot/agent authored commits.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			if globals.json {
				return printJSON(out, map[string]any{
					"status":  "stubbed",
					"command": "audit",
				})
			}

			if _, err := fmt.Fprintln(out, ui.Header("stet audit")); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, ui.Warn("stet audit report is stubbed (pending STET-7 implementation)")); err != nil {
				return err
			}
			return nil
		},
	}
}
