package github

import (
	"context"
	"time"
)

// Review is a single review left on a pull request.
type Review struct {
	AuthorLogin string
	AuthorIsBot bool
	State       string // APPROVED, CHANGES_REQUESTED, COMMENTED, DISMISSED
	SubmittedAt time.Time
}

// PR is a merged pull request into a repository's default branch, along
// with just enough review and commit metadata to compute the audit's
// definitions.
type PR struct {
	Number           int
	URL              string
	AuthorLogin      string
	AuthorIsBot      bool
	MergedByLogin    string
	MergedAt         time.Time
	CreatedAt        time.Time
	ReadyForReviewAt *time.Time
	MergeCommitSHA   string
	// TotalCommits is the number of commits on the PR's branch. For a
	// rebase merge, this many first-parent commits land on the base
	// branch ending at MergeCommitSHA (GitHub only reports the SHA of the
	// last one), so it lets the audit associate all of them with this PR
	// instead of only the last.
	TotalCommits int
	// CommitAuthorLogins are the GitHub logins of everyone who authored a
	// commit on the PR's branch (deduplicated, unlinked/absent users
	// omitted). An approval from one of them is a co-author reviewing
	// their own contribution, not independent review.
	CommitAuthorLogins []string
	FinalCommitAt      time.Time
	Reviews            []Review
}

// Client reads merged-PR review data for one repository.
type Client interface {
	// MergedPRs returns pull requests merged into base, newest first,
	// stopping once a PR's MergedAt falls before since or limit results
	// have been collected.
	MergedPRs(ctx context.Context, owner, repo, base string, since time.Time, limit int) ([]PR, error)
}
