// Package audit computes the `stet audit` report: a pure function from
// local git history (and, when available, GitHub pull request data) to a
// Report. It performs no I/O of its own; internal/gitlocal and
// internal/github gather the inputs.
//
// # Definitions
//
// These are deliberately precise so the report is falsifiable.
//
// Meaningful human review of a merged PR: at least one APPROVED review
// from a qualifying reviewer (a non-bot user who is not the PR's author),
// whose SubmittedAt is at or after the PR's final head commit's
// committedDate — an approval of the code that was actually merged, not
// of an earlier revision. A PR lacking this counts toward "no review" in
// the headline, whether because it has no approval at all, only
// disqualified approvals (bot, self), or only stale ones.
//
// A qualifying reviewer additionally excludes co-authors: anyone who
// authored a commit on the PR's branch, fetched via each commit's GitHub
// authors, cannot satisfy meaningful review by approving their own
// contribution.
//
// Headline: (merged PRs lacking meaningful review, plus direct pushes —
// first-parent commits on the default branch not associated with any
// merged PR's commits) divided by (merged PRs + direct pushes), over
// the report's window. A PR contributes every first-parent commit up to
// its total commit count, ending at the commit GitHub reports as its
// merge commit, so a rebase-merged PR's other landed commits are not
// miscounted as direct pushes. A PR dropped by --limit or by the
// GraphQL pagination window cannot be associated this way, and its
// commits are counted as direct pushes.
//
// Self-merge: a PR whose MergedByLogin equals its AuthorLogin,
// case-insensitively.
//
// Self-approval: an APPROVED review by the PR's own author. Reachable on
// GitHub only in edge cases (e.g. permission changes after the fact); it
// is reported as its own finding kind but is not, by construction, ever
// treated as satisfying "meaningful human review" and so is always folded
// into "no review" as well.
//
// Approval predates final commit: the single most recent APPROVED review
// on a PR (regardless of who submitted it) has a SubmittedAt before the
// final head commit's committedDate. This is reported alongside, not
// instead of, "no review": a PR can be both — it had an approval, but
// that approval was stale by the time the code actually merged.
//
// Approval latency: for a PR with meaningful review, the time from the
// PR's CreatedAt (or ReadyForReviewAt when GitHub reports one) to the
// *first* qualifying approval, bucketed into <5m, 5m-1h, 1h-24h, 1d-7d,
// >7d -- distinct from the *latest* qualifying approval, which is what
// decides whether the PR has meaningful review at all (it must cover the
// code that actually merged). A PR without meaningful review buckets
// into "none".
//
// Bot/agent commit: a commit whose author or committer name/email
// matches a "[bot]" suffix, a GitHub Bot account type, or one of the
// fixed agent identities in classify.go (via name, email, login, or a
// Co-authored-by trailer, matched case-insensitively). Reported as a
// share of commits per calendar month (UTC) over the window.
//
// Signature coverage: the share of first-parent default-branch commits
// whose `git log --pretty=%G?` is not "N" (i.e. carries some signature,
// whether or not git could locally verify it against a known key).
package audit
