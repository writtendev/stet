package gitlocal

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}
}

// initRepo creates a fresh repo in a temp dir with a deterministic author
// identity, so tests never depend on the host's global git config.
func initRepo(t *testing.T) string {
	t.Helper()
	requireGit(t)

	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	run("init", "--initial-branch=main")
	run("config", "user.name", "Test User")
	run("config", "user.email", "test@example.com")
	run("config", "commit.gpgsign", "false")
	return dir
}

func writeCommit(t *testing.T, dir, name, message string, trailerLines ...string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(name+"\n"), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	body := message
	if len(trailerLines) > 0 {
		body += "\n\n" + strings.Join(trailerLines, "\n")
	}

	cmd := exec.Command("git", "-C", dir, "add", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "-C", dir, "commit", "-m", body)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("rev-parse HEAD: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func TestParseGitHubRemote(t *testing.T) {
	cases := []struct {
		url       string
		wantOwner string
		wantName  string
		wantOK    bool
	}{
		{"git@github.com:writtendev/stet.git", "writtendev", "stet", true},
		{"git@github.com:writtendev/stet", "writtendev", "stet", true},
		{"https://github.com/writtendev/stet.git", "writtendev", "stet", true},
		{"https://github.com/writtendev/stet", "writtendev", "stet", true},
		{"https://user@github.com/writtendev/stet.git", "writtendev", "stet", true},
		{"ssh://git@github.com/writtendev/stet.git", "writtendev", "stet", true},
		{"ssh://git@github.com:writtendev/stet.git", "writtendev", "stet", true},
		{"https://gitlab.com/writtendev/stet.git", "", "", false},
		{"not a url", "", "", false},
	}

	for _, tc := range cases {
		owner, name, ok := ParseGitHubRemote(tc.url)
		if ok != tc.wantOK || owner != tc.wantOwner || name != tc.wantName {
			t.Errorf("ParseGitHubRemote(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.url, owner, name, ok, tc.wantOwner, tc.wantName, tc.wantOK)
		}
	}
}

func TestDefaultBranchFromSymref(t *testing.T) {
	dir := initRepo(t)
	writeCommit(t, dir, "a.txt", "first")

	remoteDir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("remote", "add", "origin", remoteDir)
	run("update-ref", "refs/remotes/origin/main", "HEAD")
	run("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")

	repo, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	branch, err := repo.DefaultBranch(context.Background(), "origin")
	if err != nil {
		t.Fatalf("DefaultBranch: %v", err)
	}
	if branch != "main" {
		t.Errorf("DefaultBranch = %q, want %q", branch, "main")
	}
}

func TestDefaultBranchFallback(t *testing.T) {
	dir := initRepo(t)
	writeCommit(t, dir, "a.txt", "first")

	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("remote", "add", "origin", t.TempDir())
	run("update-ref", "refs/remotes/origin/master", "HEAD")

	repo, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	branch, err := repo.DefaultBranch(context.Background(), "origin")
	if err != nil {
		t.Fatalf("DefaultBranch: %v", err)
	}
	if branch != "master" {
		t.Errorf("DefaultBranch = %q, want %q", branch, "master")
	}
}

func TestDefaultBranchNoneFound(t *testing.T) {
	dir := initRepo(t)
	writeCommit(t, dir, "a.txt", "first")

	repo, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := repo.DefaultBranch(context.Background(), "origin"); err == nil {
		t.Fatal("expected an error when no default branch can be determined")
	} else if !strings.Contains(err.Error(), "git remote set-head") {
		t.Errorf("expected actionable hint in error, got: %v", err)
	}
}

func TestFirstParentLogAndTrailers(t *testing.T) {
	dir := initRepo(t)
	writeCommit(t, dir, "a.txt", "first commit", "Signed-off-by: Test User <test@example.com>")
	writeCommit(t, dir, "b.txt", "second commit",
		"Co-authored-by: Claude <noreply@anthropic.com>",
		"Signed-off-by: Test User <test@example.com>")

	repo, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	commits, err := repo.FirstParentLog(context.Background(), "main", time.Time{})
	if err != nil {
		t.Fatalf("FirstParentLog: %v", err)
	}
	if len(commits) != 2 {
		t.Fatalf("expected 2 commits, got %d", len(commits))
	}

	// Log order is newest-first.
	latest := commits[0]
	if latest.SigStatus != "N" {
		t.Errorf("expected unsigned commit (SigStatus N), got %q", latest.SigStatus)
	}
	if latest.Signed() {
		t.Error("expected Signed() to be false for an unsigned commit")
	}
	if got := latest.Trailers["Co-authored-by"]; len(got) != 1 || got[0] != "Claude <noreply@anthropic.com>" {
		t.Errorf("expected Co-authored-by trailer, got %v", latest.Trailers)
	}
	if got := latest.Trailers["Signed-off-by"]; len(got) != 1 {
		t.Errorf("expected Signed-off-by trailer, got %v", latest.Trailers)
	}
	if latest.AuthorEmail != "test@example.com" {
		t.Errorf("unexpected author email: %q", latest.AuthorEmail)
	}
	if latest.IsMerge() {
		t.Error("did not expect a merge commit")
	}

	oldest := commits[1]
	if len(oldest.Trailers["Co-authored-by"]) != 0 {
		t.Errorf("did not expect Co-authored-by on first commit, got %v", oldest.Trailers)
	}
}

func TestFirstParentLogSince(t *testing.T) {
	dir := initRepo(t)
	writeCommit(t, dir, "a.txt", "first commit")
	writeCommit(t, dir, "b.txt", "second commit")

	repo, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	future := time.Now().Add(24 * time.Hour)
	commits, err := repo.FirstParentLog(context.Background(), "main", future)
	if err != nil {
		t.Fatalf("FirstParentLog: %v", err)
	}
	if len(commits) != 0 {
		t.Errorf("expected no commits after a future --since cutoff, got %d", len(commits))
	}
}

func TestFirstParentLogDanglingStaleOriginHEADIsAnError(t *testing.T) {
	dir := initRepo(t)
	writeCommit(t, dir, "a.txt", "first commit")
	writeCommit(t, dir, "b.txt", "second commit")

	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("remote", "add", "origin", t.TempDir())
	run("update-ref", "refs/remotes/origin/main", "HEAD")
	// A stale/dangling refs/remotes/origin/HEAD: it symlinks to a branch
	// that was renamed or deleted (e.g. after a default-branch rename, or
	// a prune with an older git / followRemoteHEAD=never). git
	// symbolic-ref happily reads the symref itself without checking that
	// its target exists, so DefaultBranch still reports "trunk" even
	// though refs/remotes/origin/trunk was never created.
	run("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")

	repo, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	branch, err := repo.DefaultBranch(context.Background(), "origin")
	if err != nil {
		t.Fatalf("DefaultBranch: %v", err)
	}
	if branch != "trunk" {
		t.Fatalf("expected DefaultBranch to report the dangling symref target %q, got %q", "trunk", branch)
	}

	// The repository genuinely has commits -- HEAD is not unborn -- so a
	// branch that fails to resolve here must be a real error, not a
	// silently empty history. Before the fix, any rev-parse --verify
	// failure was swallowed as "empty repo", which made this look like a
	// clean, fully-covered report with zero commits instead of surfacing
	// the broken remote-tracking state.
	if _, err := repo.FirstParentLog(context.Background(), "refs/remotes/origin/"+branch, time.Time{}); err == nil {
		t.Fatal("expected an error logging a dangling remote-tracking ref in a non-empty repository")
	}
}

func TestOpenNotAGitRepo(t *testing.T) {
	requireGit(t)
	if _, err := Open(context.Background(), t.TempDir()); err == nil {
		t.Fatal("expected an error opening a non-repository directory")
	}
}

func TestRemoteURL(t *testing.T) {
	dir := initRepo(t)
	writeCommit(t, dir, "a.txt", "first")

	cmd := exec.Command("git", "-C", dir, "remote", "add", "origin", "git@github.com:writtendev/stet.git")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git remote add: %v\n%s", err, out)
	}

	repo, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	url, err := repo.RemoteURL(context.Background(), "origin")
	if err != nil {
		t.Fatalf("RemoteURL: %v", err)
	}
	if url != "git@github.com:writtendev/stet.git" {
		t.Errorf("RemoteURL = %q", url)
	}

	if _, err := repo.RemoteURL(context.Background(), "nope"); err == nil {
		t.Error("expected an error for a nonexistent remote")
	}
}
