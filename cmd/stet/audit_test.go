package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/writtendev/stet/internal/github"
)

// fakeEnv and noGHRunner give audit's dependency-injected token resolution
// a deterministic, network-free environment: no real GH_TOKEN, GITHUB_TOKEN,
// or `gh` login is ever consulted in these tests.
type fakeEnv map[string]string

func (f fakeEnv) Getenv(key string) string { return f[key] }

type noGHRunner struct{}

func (noGHRunner) Output(ctx context.Context, name string, args ...string) (string, error) {
	return "", errors.New("gh: not logged in (test stub)")
}

// tempAuditRepo builds a hermetic git repo with a "main" default branch and
// a github.com origin remote, independent of the ambient checkout this test
// binary happens to run inside. This matters because a shallow
// `actions/checkout` (as CI uses) does not set up refs/remotes/origin/HEAD,
// so resolving the default branch against the real repo these tests live in
// would be environment-dependent; auditDeps.dir points audit at this repo
// instead.
func tempAuditRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}

	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run("init", "--initial-branch=main")
	run("config", "user.name", "Test User")
	run("config", "user.email", "test@example.com")
	run("config", "commit.gpgsign", "false")
	run("commit", "--allow-empty", "-m", "first commit")
	run("remote", "add", "origin", "git@github.com:writtendev/stet.git")
	run("update-ref", "refs/remotes/origin/main", "HEAD")
	run("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")

	return dir
}

func executeAuditCmd(deps auditDeps, args ...string) (string, error) {
	cmd := newAuditCmdWithDeps(func() auditDeps { return deps })
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestAuditJSONShapeWithFakeClient(t *testing.T) {
	globals.json = true
	globals.verbose = false
	defer func() { globals.json = false }()

	now := time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
	fc := &github.FakeClient{PRs: []github.PR{
		{
			Number:        1,
			URL:           "https://github.com/writtendev/stet/pull/1",
			AuthorLogin:   "alice",
			MergedByLogin: "bob",
			CreatedAt:     now.AddDate(0, 0, -10),
			MergedAt:      now.AddDate(0, 0, -9),
			FinalCommitAt: now.AddDate(0, 0, -10),
			Reviews: []github.Review{
				{AuthorLogin: "bob", State: "APPROVED", SubmittedAt: now.AddDate(0, 0, -10).Add(time.Hour)},
			},
		},
	}}

	deps := auditDeps{
		dir:       tempAuditRepo(t),
		env:       fakeEnv{"GH_TOKEN": "test-token"},
		runner:    noGHRunner{},
		newClient: func(token string) github.Client { return fc },
		now:       func() time.Time { return now },
	}

	// --json is normally a persistent flag inherited from the root
	// command; this test drives newAuditCmdWithDeps standalone, so it
	// sets the globals.json switch directly instead of passing the flag.
	out, err := executeAuditCmd(deps)
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, out)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("invalid json: %v, raw: %s", err, out)
	}

	sources, ok := payload["sources"].(map[string]any)
	if !ok || sources["github"] != true {
		t.Fatalf("expected sources.github == true, got: %+v", payload["sources"])
	}
	if payload["token_source"] != "env:GH_TOKEN" {
		t.Errorf("expected token_source env:GH_TOKEN, got: %v", payload["token_source"])
	}
	headline, ok := payload["headline"].(map[string]any)
	if !ok {
		t.Fatalf("expected a non-null headline when the GitHub tier is available, got: %v", payload["headline"])
	}
	if total, _ := headline["total"].(float64); total < 1 {
		t.Errorf("expected at least the 1 fake PR counted in total, got: %v", headline["total"])
	}
	if fc.Calls != 1 {
		t.Errorf("expected the fake client to be called exactly once, got %d", fc.Calls)
	}
	if strings.Contains(out, "test-token") {
		t.Error("the raw token value must never appear in --json output")
	}
}

func TestAuditOfflineNeverCallsClient(t *testing.T) {
	globals.json = false
	globals.verbose = false

	failing := &github.FailingClient{Fail: func(msg string) { t.Fatal(msg) }}
	deps := auditDeps{
		dir:       tempAuditRepo(t),
		env:       fakeEnv{"GH_TOKEN": "test-token"},
		runner:    noGHRunner{},
		newClient: func(token string) github.Client { return failing },
		now:       func() time.Time { return time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC) },
	}

	out, err := executeAuditCmd(deps, "--offline")
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "STET AUDIT") {
		t.Errorf("expected human-readable audit output, got: %s", out)
	}
	if !strings.Contains(out, "--offline") {
		t.Errorf("expected the offline warning to name --offline, got: %s", out)
	}
}

func TestAuditOfflineSkipsTokenResolutionEntirely(t *testing.T) {
	globals.json = false
	globals.verbose = false

	// A runner that fails the test if it's ever invoked: --offline must
	// short-circuit before any token resolution attempt at all.
	deps := auditDeps{
		dir:    tempAuditRepo(t),
		env:    fakeEnv{},
		runner: failingRunner{fail: func(msg string) { t.Error(msg) }},
		newClient: func(token string) github.Client {
			t.Fatal("newClient should never be called with --offline")
			return nil
		},
		now: func() time.Time { return time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC) },
	}

	if _, err := executeAuditCmd(deps, "--offline"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

type failingRunner struct{ fail func(string) }

func (f failingRunner) Output(ctx context.Context, name string, args ...string) (string, error) {
	if f.fail != nil {
		f.fail("Output should not be called with --offline")
	}
	return "", errors.New("should not be called")
}

func TestAuditHumanOutputContainsHeadline(t *testing.T) {
	globals.json = false
	globals.verbose = false

	now := time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
	fc := &github.FakeClient{PRs: []github.PR{
		{
			Number:        2,
			URL:           "https://github.com/writtendev/stet/pull/2",
			AuthorLogin:   "alice",
			MergedByLogin: "alice",
			CreatedAt:     now.AddDate(0, 0, -5),
			MergedAt:      now.AddDate(0, 0, -4),
			FinalCommitAt: now.AddDate(0, 0, -5),
		},
	}}

	deps := auditDeps{
		dir:       tempAuditRepo(t),
		env:       fakeEnv{"GH_TOKEN": "test-token"},
		runner:    noGHRunner{},
		newClient: func(token string) github.Client { return fc },
		now:       func() time.Time { return now },
	}

	out, err := executeAuditCmd(deps)
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "% of merges") {
		t.Errorf("expected the headline percentage line in human output, got: %s", out)
	}
}
