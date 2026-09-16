package audit

import (
	"encoding/json"
	"testing"

	"github.com/writtendev/stet/internal/github"
	"github.com/writtendev/stet/internal/gitlocal"
)

func TestJSONDeterministic(t *testing.T) {
	now := t0("2025-07-01T00:00:00Z")
	input := Input{
		Repo:            "writtendev/stet",
		DefaultBranch:   "main",
		Months:          6,
		GitHubAvailable: true,
		TokenSource:     "env:GH_TOKEN",
		Commits: []gitlocal.Commit{
			{SHA: "c1", AuthorName: "Alice", CommittedAt: t0("2025-06-10T00:00:00Z"), SigStatus: "G"},
			{SHA: "c2", AuthorName: "dependabot[bot]", CommittedAt: t0("2025-06-11T00:00:00Z"), SigStatus: "N"},
		},
		PRs: []github.PR{basePR(1), basePR(2)},
	}

	first, err := json.Marshal(Build(input, now))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	second, err := json.Marshal(Build(input, now))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if string(first) != string(second) {
		t.Errorf("expected byte-identical JSON across two runs with the same input:\n%s\nvs\n%s", first, second)
	}
}

func TestJSONOfflineFieldsAreNull(t *testing.T) {
	now := t0("2025-07-01T00:00:00Z")
	report := Build(Input{DefaultBranch: "main", Months: 6}, now)

	b, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if raw["headline"] != nil {
		t.Errorf("expected headline to be null offline, got %v", raw["headline"])
	}
	if raw["merges"] != nil {
		t.Errorf("expected merges to be null offline, got %v", raw["merges"])
	}
	sources, ok := raw["sources"].(map[string]any)
	if !ok || sources["github"] != false {
		t.Errorf("expected sources.github == false offline, got %v", raw["sources"])
	}
}
