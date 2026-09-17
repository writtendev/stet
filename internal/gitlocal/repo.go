// Package gitlocal reads commit and remote metadata from a local git
// repository by shelling out to the git CLI. It never touches the network:
// every command it runs is a read against on-disk git state.
package gitlocal

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Commit is one entry in a first-parent commit log.
type Commit struct {
	SHA            string
	AuthorName     string
	AuthorEmail    string
	CommitterName  string
	CommitterEmail string
	CommittedAt    time.Time
	Parents        []string
	// Message is the commit's full raw message (git's %B: subject and
	// body, trailers included). Used to positively match a rebase-merged
	// commit replayed onto the base branch under a new SHA back to the
	// original commit it came from, since a rebase only changes the
	// parent (and so the hash and committer date) and keeps the author
	// and message identical.
	Message string
	// Trailers holds RFC-822-style trailer lines found in the commit body
	// (e.g. "Co-authored-by", "Signed-off-by"), keyed by trailer name with
	// original casing preserved. A trailer may repeat, so each value is a
	// slice in the order it appeared.
	Trailers map[string][]string
	// SigStatus is the raw `git log --pretty=%G?` code: "G"/"U"/"X"/"Y"/"R"
	// for a signature git considers good in some sense, "B" bad, "E"
	// unverifiable, "N" no signature at all.
	SigStatus string
}

// Signed reports whether the commit carries any signature, regardless of
// whether that signature could be locally verified.
func (c Commit) Signed() bool {
	return c.SigStatus != "" && c.SigStatus != "N"
}

// IsMerge reports whether the commit has more than one parent.
func (c Commit) IsMerge() bool {
	return len(c.Parents) > 1
}

// Repo is a handle onto a local git working copy.
type Repo struct {
	dir string
}

// Open verifies dir is inside a git working tree and returns a handle onto
// it. It performs no network access.
func Open(ctx context.Context, dir string) (*Repo, error) {
	r := &Repo{dir: dir}
	if _, err := r.run(ctx, "rev-parse", "--is-inside-work-tree"); err != nil {
		return nil, fmt.Errorf("gitlocal: %q is not inside a git repository: %w", dir, err)
	}
	return r, nil
}

// RemoteURL returns the fetch URL configured for remote.
func (r *Repo) RemoteURL(ctx context.Context, remote string) (string, error) {
	out, err := r.run(ctx, "remote", "get-url", remote)
	if err != nil {
		return "", fmt.Errorf("gitlocal: no remote named %q: %w", remote, err)
	}
	return strings.TrimSpace(out), nil
}

// CurrentBranch returns the repository's currently checked-out branch
// name, or the literal "HEAD" when it is in a detached-HEAD state (which
// git log and other plumbing accept as a ref just as well as a branch
// name). Used as a local-only fallback when no remote-tracking default
// branch can be resolved, so the git tier can still run.
func (r *Repo) CurrentBranch(ctx context.Context) (string, error) {
	out, err := r.run(ctx, "rev-parse", "--abbrev-ref", "HEAD")
	if err == nil {
		return strings.TrimSpace(out), nil
	}
	// `rev-parse --abbrev-ref HEAD` fails on an unborn HEAD (a brand-new
	// repository with no commits yet): there is no commit for it to
	// abbreviate a ref towards. The symbolic ref itself still resolves in
	// that state, so fall back to reading it directly rather than failing
	// a repo that simply has nothing committed yet.
	if out, symErr := r.run(ctx, "symbolic-ref", "--short", "HEAD"); symErr == nil {
		return strings.TrimSpace(out), nil
	}
	return "", fmt.Errorf("gitlocal: resolving current branch: %w", err)
}

// DefaultBranch resolves the default branch of remote: first via the
// tracked refs/remotes/<remote>/HEAD symref (as set by `git clone` or
// `git remote set-head`), falling back to a "main" or "master" branch if
// either exists on the remote. It returns an actionable error otherwise.
func (r *Repo) DefaultBranch(ctx context.Context, remote string) (string, error) {
	ref, err := r.run(ctx, "symbolic-ref", fmt.Sprintf("refs/remotes/%s/HEAD", remote))
	if err == nil {
		ref = strings.TrimSpace(ref)
		prefix := fmt.Sprintf("refs/remotes/%s/", remote)
		if branch, ok := strings.CutPrefix(ref, prefix); ok && branch != "" {
			return branch, nil
		}
	}

	for _, candidate := range []string{"main", "master"} {
		if _, err := r.run(ctx, "show-ref", "--verify", "--quiet", fmt.Sprintf("refs/remotes/%s/%s", remote, candidate)); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf(
		"gitlocal: could not determine the default branch for remote %q; run `git remote set-head %s -a`",
		remote, remote,
	)
}

// Field/record separators chosen to never appear in ordinary commit
// metadata or message bodies.
const (
	fieldSep  = "\x1f"
	recordSep = "\x1e"
)

var logFormat = strings.Join([]string{
	"%H", "%an", "%ae", "%cn", "%ce", "%cI", "%P", "%G?", "%B",
}, fieldSep) + recordSep

// unbornHEAD reports whether the repository genuinely has no commits at
// all yet -- a fresh `git init` with nothing committed. It is the only
// case in which a ref failing to resolve is not an error: any other ref
// resolution failure (a branch that was never fetched, a dangling
// refs/remotes/<remote>/HEAD symref left pointing at a deleted or
// renamed branch) is a real problem with real commits sitting right
// there, not an empty repository, and must not be reported as one.
func (r *Repo) unbornHEAD(ctx context.Context) bool {
	_, err := r.run(ctx, "rev-parse", "--verify", "--quiet", "HEAD")
	return err != nil
}

// FirstParentLog returns the first-parent commit history of branch,
// optionally limited to commits committed at or after since (a zero
// since returns the full history). branch resolving to no commit at all
// is an error, unless the repository as a whole is unborn -- a
// brand-new repository with nothing committed yet -- in which case it
// returns an empty history, so a fresh `git init` still produces a
// report instead of a hard failure. A branch that fails to resolve in a
// repository that genuinely has commits (e.g. a stale or dangling
// refs/remotes/<remote>/HEAD symref pointing at a deleted or renamed
// branch) is not silently treated as empty: that would produce a report
// claiming zero commits and 0% coverage against real history.
func (r *Repo) FirstParentLog(ctx context.Context, branch string, since time.Time) ([]Commit, error) {
	if _, err := r.run(ctx, "rev-parse", "--verify", "--quiet", branch); err != nil {
		if r.unbornHEAD(ctx) {
			return nil, nil
		}
		return nil, fmt.Errorf("gitlocal: branch %q does not resolve to a commit: %w", branch, err)
	}

	args := []string{"log", "--first-parent", "--date=iso-strict", "--pretty=format:" + logFormat}
	if !since.IsZero() {
		args = append(args, "--since="+since.UTC().Format(time.RFC3339))
	}
	args = append(args, branch)

	out, err := r.run(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("gitlocal: log %q: %w", branch, err)
	}

	var commits []Commit
	for _, record := range strings.Split(out, recordSep) {
		record = strings.TrimPrefix(record, "\n")
		if strings.TrimSpace(record) == "" {
			continue
		}
		fields := strings.SplitN(record, fieldSep, 9)
		if len(fields) < 9 {
			continue
		}
		committedAt, err := time.Parse(time.RFC3339, fields[5])
		if err != nil {
			return nil, fmt.Errorf("gitlocal: parsing committed date %q: %w", fields[5], err)
		}
		var parents []string
		if p := strings.TrimSpace(fields[6]); p != "" {
			parents = strings.Fields(p)
		}
		commits = append(commits, Commit{
			SHA:            fields[0],
			AuthorName:     fields[1],
			AuthorEmail:    fields[2],
			CommitterName:  fields[3],
			CommitterEmail: fields[4],
			CommittedAt:    committedAt,
			Parents:        parents,
			Message:        fields[8],
			SigStatus:      fields[7],
			Trailers:       parseTrailers(fields[8]),
		})
	}
	return commits, nil
}

var trailerLineRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*): (.+)$`)

// parseTrailers extracts a trailing block of "Key: value" lines from a
// commit message body, in the style of git-interpret-trailers.
func parseTrailers(body string) map[string][]string {
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")

	end := len(lines)
	start := end
	for i := end - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			if start != end {
				break
			}
			end--
			continue
		}
		if !trailerLineRE.MatchString(line) {
			break
		}
		start = i
	}

	trailers := map[string][]string{}
	for i := start; i < end; i++ {
		m := trailerLineRE.FindStringSubmatch(strings.TrimSpace(lines[i]))
		if m == nil {
			continue
		}
		trailers[m[1]] = append(trailers[m[1]], m[2])
	}
	return trailers
}

var (
	githubSSHRE      = regexp.MustCompile(`^git@github\.com:([^/]+)/(.+?)(\.git)?$`)
	githubSSHProtoRE = regexp.MustCompile(`^ssh://git@github\.com[/:]([^/]+)/(.+?)(\.git)?$`)
	githubHTTPSRE    = regexp.MustCompile(`^https?://(?:[^@/]+@)?github\.com/([^/]+)/(.+?)(\.git)?$`)
)

// ParseGitHubRemote extracts an owner/repo pair from a github.com remote
// URL in its https, ssh://, or scp-like git@ forms. ok is false for any
// other host or an unrecognized shape.
func ParseGitHubRemote(url string) (owner, name string, ok bool) {
	url = strings.TrimSpace(url)
	for _, re := range []*regexp.Regexp{githubSSHRE, githubSSHProtoRE, githubHTTPSRE} {
		if m := re.FindStringSubmatch(url); m != nil {
			return m[1], m[2], true
		}
	}
	return "", "", false
}

func (r *Repo) run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", r.dir}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s", msg)
	}
	return stdout.String(), nil
}
