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

// PRCommit is one commit that was part of a PR's branch history (as
// GitHub reports it pre-merge), carrying just enough to positively match
// it against a first-parent commit on the base branch: a rebase merge
// replays each of these under a new SHA (only the parent, and so the
// hash and committer date, changes), while a squash or merge-commit
// merge never reproduces them on the base branch's first-parent chain at
// all.
type PRCommit struct {
	Message     string
	AuthorName  string
	AuthorEmail string
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
	// TotalCommits is the number of commits on the PR's branch, sampled
	// up to the GraphQL query's own cap (see mergedPRsQuery). Informational
	// only: countDirectPushes in internal/audit/compute.go associates
	// commits by matching Commits below, not by trusting this count.
	TotalCommits int
	// Commits are the PR's own commits (bounded by the same cap as
	// TotalCommits), used to positively identify which first-parent
	// commits on the base branch are this PR's doing after a rebase
	// merge.
	Commits []PRCommit
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
