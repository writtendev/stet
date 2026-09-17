package audit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/writtendev/stet/internal/github"
	"github.com/writtendev/stet/internal/gitlocal"
)

func TestRenderOfflineReport(t *testing.T) {
	now := t0("2025-07-01T00:00:00Z")
	report := Build(Input{
		Repo:          "writtendev/stet",
		DefaultBranch: "main",
		Months:        6,
		Commits: []gitlocal.Commit{
			{SHA: "c1", AuthorName: "Alice", CommittedAt: t0("2025-06-10T00:00:00Z"), SigStatus: "N"},
		},
	}, now)

	var buf bytes.Buffer
	if err := Render(&buf, report); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "STET AUDIT") {
		t.Errorf("expected header, got:\n%s", out)
	}
	if !strings.Contains(out, "SIGNATURES") {
		t.Errorf("expected a signatures section, got:\n%s", out)
	}
	if strings.Contains(out, "no meaningful human review") {
		t.Errorf("did not expect a headline percentage when GitHub tier is unavailable, got:\n%s", out)
	}
}

func TestRenderGitHubReport(t *testing.T) {
	now := t0("2025-07-01T00:00:00Z")
	pr := basePR(1)
	report := Build(Input{
		Repo:            "writtendev/stet",
		DefaultBranch:   "main",
		Months:          6,
		GitHubAvailable: true,
		PRs:             []github.PR{pr},
	}, now)

	var buf bytes.Buffer
	if err := Render(&buf, report); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "% of merges") {
		t.Errorf("expected the headline percentage line, got:\n%s", out)
	}
	if !strings.Contains(out, "APPROVAL LATENCY") {
		t.Errorf("expected an approval latency section, got:\n%s", out)
	}
	for _, unwanted := range []string{"⣾", "⠋"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output should carry no spinner glyphs: found %q", unwanted)
		}
	}
}
