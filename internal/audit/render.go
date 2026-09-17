package audit

import (
	"fmt"
	"io"

	"github.com/writtendev/stet/internal/ui"
)

// Render writes a paper-and-ink human-readable rendering of report to w:
// the headline first as a bold percentage, then aligned key/value
// sections, and a plain bucket table. No color beyond the ui package's
// ink palette, and no animation.
func Render(w io.Writer, report Report) error {
	if err := writeln(w, ui.Header("stet audit")); err != nil {
		return err
	}
	if err := writeln(w, ui.KeyValue("Repository", valueOr(report.Repo, "(no GitHub remote)"))); err != nil {
		return err
	}
	if err := writeln(w, ui.KeyValue("Default Branch", report.DefaultBranch)); err != nil {
		return err
	}
	if report.Sources.DefaultBranchFallback != "" {
		if err := writeln(w, ui.Warn(report.Sources.DefaultBranchFallback)); err != nil {
			return err
		}
	}
	if err := writeln(w, ui.KeyValue("Window", fmt.Sprintf(
		"%d months (%s to %s)", report.Window.Months,
		report.Window.Since.Format("2006-01-02"), report.Window.Until.Format("2006-01-02"),
	))); err != nil {
		return err
	}

	if err := ui.FprintDivider(w, 60); err != nil {
		return err
	}

	if report.Headline != nil {
		if err := writeln(w, ui.Bold.Render(fmt.Sprintf(
			"%.1f%% of merges to %s had no meaningful human review",
			report.Headline.Share*100, report.DefaultBranch,
		))); err != nil {
			return err
		}
		if err := writeln(w, ui.KeyValue("Missing Review", fmt.Sprintf(
			"%d / %d", report.Headline.NoMeaningfulReview, report.Headline.Total,
		))); err != nil {
			return err
		}
	} else {
		reason := report.Sources.GitHubUnavailableReason
		if reason == "" {
			reason = "GitHub review data unavailable"
		}
		if err := writeln(w, ui.Warn(reason)); err != nil {
			return err
		}
	}

	if report.Merges != nil {
		if err := ui.FprintDivider(w, 60); err != nil {
			return err
		}
		if err := writeln(w, ui.Header("Merges")); err != nil {
			return err
		}
		rows := [][2]string{
			{"Total", fmt.Sprintf("%d", report.Merges.Total)},
			{"No Review", fmt.Sprintf("%d", report.Merges.NoReview)},
			{"Self-Merged", fmt.Sprintf("%d", report.Merges.SelfMerged)},
			{"Self-Approved", fmt.Sprintf("%d", report.Merges.SelfApproved)},
			{"Stale Approval", fmt.Sprintf("%d", report.Merges.ApprovalPredatesFinalCommit)},
			{"Direct Pushes", fmt.Sprintf("%d", report.Merges.DirectPushes)},
		}
		for _, row := range rows {
			if err := writeln(w, ui.KeyValue(row[0], row[1])); err != nil {
				return err
			}
		}
	}

	if len(report.ApprovalLatency) > 0 {
		if err := ui.FprintDivider(w, 60); err != nil {
			return err
		}
		if err := writeln(w, ui.Header("Approval Latency")); err != nil {
			return err
		}
		for _, b := range report.ApprovalLatency {
			if err := writeln(w, ui.KeyValue(b.Bucket, fmt.Sprintf("%d", b.Count))); err != nil {
				return err
			}
		}
	}

	if err := ui.FprintDivider(w, 60); err != nil {
		return err
	}
	if err := writeln(w, ui.Header("Signatures")); err != nil {
		return err
	}
	if err := writeln(w, ui.KeyValue("Signed Commits", fmt.Sprintf(
		"%d / %d", report.Signatures.Signed, report.Signatures.Commits,
	))); err != nil {
		return err
	}

	if len(report.BotAgentShare) > 0 {
		if err := ui.FprintDivider(w, 60); err != nil {
			return err
		}
		if err := writeln(w, ui.Header("Bot/Agent Commit Share")); err != nil {
			return err
		}
		for _, m := range report.BotAgentShare {
			if err := writeln(w, ui.KeyValue(m.Month, fmt.Sprintf(
				"%d / %d (%.1f%%)", m.BotAgent, m.Commits, m.Share*100,
			))); err != nil {
				return err
			}
		}
	}

	return nil
}

func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func writeln(w io.Writer, s string) error {
	_, err := fmt.Fprintln(w, s)
	return err
}
