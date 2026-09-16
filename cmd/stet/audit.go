package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
	"github.com/writtendev/stet/internal/audit"
	"github.com/writtendev/stet/internal/github"
	"github.com/writtendev/stet/internal/gitlocal"
	"github.com/writtendev/stet/internal/ui"
)

// auditFlags holds the audit command's own flags, separate from the
// persistent --json/--verbose globals.
type auditFlags struct {
	months  int
	limit   int
	offline bool
	remote  string
}

// auditDeps are the audit command's external dependencies, gathered
// behind small interfaces so tests can supply a fake GitHub client, a
// fixed clock, and a fake environment without any network access or
// dependence on the operator's real credentials.
type auditDeps struct {
	// dir is the working tree audit reads. Empty means the real process
	// working directory; tests point it at a hermetic temp repo so they
	// never depend on the ambient checkout's remote-tracking refs (a
	// shallow `actions/checkout` does not set refs/remotes/origin/HEAD).
	dir           string
	env           github.Env
	runner        github.Runner
	newClient     func(token string) github.Client
	newDeviceFlow func(out io.Writer) github.DeviceFlow
	now           func() time.Time
	interactive   bool
}

// execRunner shells out to real external commands (just `gh auth token`,
// in practice). It touches no network itself; whatever it invokes might.
type execRunner struct{}

func (execRunner) Output(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func defaultAuditDeps() auditDeps {
	return auditDeps{
		env:    github.OSEnv{},
		runner: execRunner{},
		newClient: func(token string) github.Client {
			return github.NewGraphQLClient(token)
		},
		newDeviceFlow: github.NewDeviceFlow,
		now:           time.Now,
		interactive:   !globals.json && ui.IsTerminal(os.Stdin) && ui.IsTerminal(os.Stderr),
	}
}

func newAuditCmd() *cobra.Command {
	return newAuditCmdWithDeps(defaultAuditDeps)
}

// newAuditCmdWithDeps builds the audit command against a deps factory,
// so tests can substitute fakes while production wiring stays the
// single defaultAuditDeps call above.
func newAuditCmdWithDeps(depsFn func() auditDeps) *cobra.Command {
	flags := auditFlags{months: 6, limit: 500, remote: "origin"}

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Generate a zero-config repository human review audit",
		Long: `Audits repository commit history and, when a GitHub token and remote are
available, merged pull request reviews, to assess human approval coverage,
latency, self-merges, and bot/agent authored commits. Runs entirely offline
against local git state when no GitHub tier is available or --offline is
set.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAudit(cmd, flags, depsFn())
		},
	}

	cmd.Flags().IntVar(&flags.months, "months", 6, "Number of trailing months to audit")
	// A PR dropped by this cutoff cannot be told apart from a genuine
	// direct push (see countDirectPushes in internal/audit/compute.go),
	// so a repo with more merged PRs in the window than --limit will see
	// its direct-push count, and headline, inflated; raise --limit (or
	// narrow --months) rather than trusting a truncated report.
	cmd.Flags().IntVar(&flags.limit, "limit", 500, "Maximum merged pull requests to fetch from GitHub")
	cmd.Flags().BoolVar(&flags.offline, "offline", false, "Skip the GitHub tier; report only what local git can determine")
	cmd.Flags().StringVar(&flags.remote, "remote", "origin", "Git remote to audit")

	return cmd
}

func runAudit(cmd *cobra.Command, flags auditFlags, deps auditDeps) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()

	dir := deps.dir
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("audit: %w", err)
		}
	}

	repo, err := gitlocal.Open(ctx, dir)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	// Resolving the default branch needs the remote's tracking refs.
	// Per the offline-invariant reconciliation, only "not a git repo" is
	// fatal: a local-only repo (no remote, or a remote without a
	// resolvable HEAD/main/master) must still produce a git-tier report,
	// falling back to whatever is actually checked out. defaultBranchErr
	// is threaded through to resolveGitHubTier, since a GitHub tier query
	// needs the real default branch name and cannot run on this fallback.
	defaultBranch, defaultBranchErr := repo.DefaultBranch(ctx, flags.remote)
	logRef := fmt.Sprintf("refs/remotes/%s/%s", flags.remote, defaultBranch)
	if defaultBranchErr != nil {
		defaultBranch, err = repo.CurrentBranch(ctx)
		if err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		logRef = defaultBranch
	}

	now := deps.now()
	if now.IsZero() {
		now = time.Now()
	}
	months := flags.months
	if months <= 0 {
		months = 6
	}
	since := now.UTC().AddDate(0, -months, 0)

	// logRef names the remote-tracking ref (refs/remotes/<remote>/<branch>)
	// rather than the bare branch name, so this always logs the remote's
	// default branch as GitHub sees it, not whatever the local branch of
	// the same name happens to point at -- which can be behind (hiding
	// merges GitHub already reports) or ahead (miscounting local-only
	// commits as direct pushes to the default branch).
	commits, err := repo.FirstParentLog(ctx, logRef, since)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	input := audit.Input{
		DefaultBranch: defaultBranch,
		Months:        months,
		Commits:       commits,
	}

	remoteURL, remoteErr := repo.RemoteURL(ctx, flags.remote)
	var owner, name string
	var isGitHub bool
	if remoteErr == nil {
		owner, name, isGitHub = gitlocal.ParseGitHubRemote(remoteURL)
		if isGitHub {
			input.Repo = owner + "/" + name
		}
	}

	resolveGitHubTier(ctx, &input, flags, deps, errOut, defaultBranchErr, remoteErr, owner, name, isGitHub, defaultBranch, since)

	report := audit.Build(input, now)

	if globals.json {
		return printJSON(out, report)
	}

	// audit.Render already surfaces report.Sources.GitHubUnavailableReason
	// as a ui.Warn line in the report body, so it is not repeated here.
	return audit.Render(out, report)
}

// resolveGitHubTier fills in the GitHub-tier fields of input, or its
// GitHubUnavailableReason, degrading gracefully rather than failing the
// whole command: per the offline-invariant reconciliation, the git tier
// above always runs, and this tier is best-effort.
func resolveGitHubTier(
	ctx context.Context,
	input *audit.Input,
	flags auditFlags,
	deps auditDeps,
	errOut io.Writer,
	defaultBranchErr error,
	remoteErr error,
	owner, name string,
	isGitHub bool,
	defaultBranch string,
	since time.Time,
) {
	switch {
	case flags.offline:
		input.GitHubUnavailableReason = "skipped: --offline"
		return
	case defaultBranchErr != nil:
		input.GitHubUnavailableReason = fmt.Sprintf("could not resolve remote %q's default branch: %v", flags.remote, defaultBranchErr)
		return
	case remoteErr != nil:
		input.GitHubUnavailableReason = fmt.Sprintf("no remote named %q", flags.remote)
		return
	case !isGitHub:
		input.GitHubUnavailableReason = fmt.Sprintf("remote %q is not a github.com remote", flags.remote)
		return
	}

	var flow github.DeviceFlow
	if deps.interactive && deps.newDeviceFlow != nil {
		flow = deps.newDeviceFlow(errOut)
	}

	token, source, err := github.ResolveToken(ctx, deps.env, deps.runner, flow, deps.interactive)
	if err != nil {
		input.GitHubUnavailableReason = err.Error()
		return
	}

	if globals.verbose && !globals.json {
		_, _ = fmt.Fprintln(errOut, ui.Muted.Render(fmt.Sprintf("fetching up to %d pull requests…", flags.limit)))
	}

	client := deps.newClient(token)
	prs, err := client.MergedPRs(ctx, owner, name, defaultBranch, since, flags.limit)
	if err != nil {
		input.GitHubUnavailableReason = fmt.Sprintf("github: %v", err)
		return
	}

	input.GitHubAvailable = true
	input.TokenSource = string(source)
	input.PRs = prs
}
