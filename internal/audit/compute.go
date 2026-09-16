package audit

import (
	"math"
	"sort"
	"strings"
	"time"

	"github.com/writtendev/stet/internal/github"
	"github.com/writtendev/stet/internal/gitlocal"
)

// Input is everything Build needs: local commit history is always
// present; GitHub PR data is present only when the GitHub tier ran.
type Input struct {
	Repo          string
	DefaultBranch string
	Months        int

	Commits []gitlocal.Commit

	GitHubAvailable         bool
	GitHubUnavailableReason string
	TokenSource             string
	PRs                     []github.PR
}

// Build computes a complete Report from Input as of now. It is pure: the
// same Input and now always produce byte-identical JSON.
func Build(in Input, now time.Time) Report {
	months := in.Months
	if months <= 0 {
		months = 6
	}
	since := now.UTC().AddDate(0, -months, 0)

	report := Report{
		Repo:          in.Repo,
		DefaultBranch: in.DefaultBranch,
		Window:        Window{Since: since, Until: now.UTC(), Months: months},
		Sources: Sources{
			Git:                     true,
			GitHub:                  in.GitHubAvailable,
			GitHubUnavailableReason: in.GitHubUnavailableReason,
		},
		TokenSource:   in.TokenSource,
		Signatures:    computeSignatures(in.Commits),
		BotAgentShare: botAgentShareByMonth(in.Commits, since),
	}

	if !in.GitHubAvailable {
		return report
	}

	buildGitHubTier(&report, in)
	return report
}

func computeSignatures(commits []gitlocal.Commit) Signatures {
	signed := 0
	for _, c := range commits {
		if c.Signed() {
			signed++
		}
	}
	return Signatures{Commits: len(commits), Signed: signed}
}

func botAgentShareByMonth(commits []gitlocal.Commit, since time.Time) []MonthShare {
	type acc struct{ total, bot int }
	months := map[string]*acc{}
	var order []string

	for _, c := range commits {
		if c.CommittedAt.Before(since) {
			continue
		}
		key := c.CommittedAt.UTC().Format("2006-01")
		a, ok := months[key]
		if !ok {
			a = &acc{}
			months[key] = a
			order = append(order, key)
		}
		a.total++
		if IsBotOrAgentCommit(c.AuthorName, c.AuthorEmail, c.CommitterName, c.CommitterEmail, c.Trailers) {
			a.bot++
		}
	}

	sort.Strings(order)
	result := make([]MonthShare, 0, len(order))
	for _, k := range order {
		a := months[k]
		result = append(result, MonthShare{
			Month:    k,
			Commits:  a.total,
			BotAgent: a.bot,
			Share:    round4(safeShare(a.bot, a.total)),
		})
	}
	return result
}

// prAnalysis is the per-PR verdict used to build merges/headline/findings.
type prAnalysis struct {
	meaningfulReview    bool
	latencyBucket       string
	predatesFinalCommit bool
	selfMerged          bool
	selfApproved        bool
}

func analyzePR(pr github.PR) prAnalysis {
	// latestApproval tracks any APPROVED review (qualifying or not) for
	// the predates-final-commit check. earliestQualifying/latestQualifying
	// track only qualifying approvals: the earliest sets the approval
	// latency (time to first qualifying approval, per the brief),
	// separately from the latest, which decides whether the PR has
	// meaningful review at all (it must cover the code that actually
	// merged).
	var latestApproval, earliestQualifying, latestQualifying *github.Review

	for i := range pr.Reviews {
		rv := &pr.Reviews[i]
		if rv.State != "APPROVED" {
			continue
		}
		if latestApproval == nil || rv.SubmittedAt.After(latestApproval.SubmittedAt) {
			latestApproval = rv
		}
		if isQualifyingApprover(*rv, pr) {
			if earliestQualifying == nil || rv.SubmittedAt.Before(earliestQualifying.SubmittedAt) {
				earliestQualifying = rv
			}
			if latestQualifying == nil || rv.SubmittedAt.After(latestQualifying.SubmittedAt) {
				latestQualifying = rv
			}
		}
	}

	a := prAnalysis{
		selfMerged:   strings.EqualFold(pr.MergedByLogin, pr.AuthorLogin) && pr.MergedByLogin != "",
		selfApproved: hasSelfApproval(pr),
	}

	if latestApproval != nil && latestApproval.SubmittedAt.Before(pr.FinalCommitAt) {
		a.predatesFinalCommit = true
	}

	if latestQualifying != nil && !latestQualifying.SubmittedAt.Before(pr.FinalCommitAt) {
		a.meaningfulReview = true
		start := pr.CreatedAt
		if pr.ReadyForReviewAt != nil {
			start = *pr.ReadyForReviewAt
		}
		a.latencyBucket = bucketFor(earliestQualifying.SubmittedAt.Sub(start))
	} else {
		a.latencyBucket = "none"
	}

	return a
}

// isQualifyingApprover reports whether rv is an independent reviewer of
// pr: not a bot/agent, not pr's own author, and not one of the people who
// authored a commit on pr's branch (a co-author approving their own
// contribution is not independent review either).
func isQualifyingApprover(rv github.Review, pr github.PR) bool {
	if IsBotOrAgentLogin(rv.AuthorLogin, rv.AuthorIsBot) {
		return false
	}
	if strings.EqualFold(rv.AuthorLogin, pr.AuthorLogin) {
		return false
	}
	for _, login := range pr.CommitAuthorLogins {
		if strings.EqualFold(rv.AuthorLogin, login) {
			return false
		}
	}
	return true
}

func hasSelfApproval(pr github.PR) bool {
	for _, rv := range pr.Reviews {
		if rv.State == "APPROVED" && strings.EqualFold(rv.AuthorLogin, pr.AuthorLogin) {
			return true
		}
	}
	return false
}

func bucketFor(d time.Duration) string {
	switch {
	case d < 5*time.Minute:
		return "<5m"
	case d < time.Hour:
		return "5m-1h"
	case d < 24*time.Hour:
		return "1h-24h"
	case d < 7*24*time.Hour:
		return "1d-7d"
	default:
		return ">7d"
	}
}

// countDirectPushes counts first-parent default-branch commits not
// associated with any fetched merged PR. A PR contributes its own commit
// count (TotalCommits) worth of first-parent commits ending at its
// MergeCommitSHA: for squash and merge-commit strategies that is just the
// one landed commit, but for a rebase merge GitHub lands every rebased
// commit as its own first-parent commit and only the last one is
// reported as MergeCommitSHA, so counting just that single SHA would
// wrongly count the other rebased commits as direct pushes. Any
// first-parent commit that is not associated with a PR this way is a
// direct push, including a true merge commit pushed straight to the
// branch (e.g. a local `git merge && git push`) -- unlike a bare
// !IsMerge() check, this does not exempt merge commits just because they
// have two parents.
//
// A PR whose merge commit falls outside in.Commits (dropped by --limit,
// or by the GraphQL pagination window) cannot be associated and its
// commits are counted as direct pushes; widen --limit or --months to
// avoid this.
func countDirectPushes(commits []gitlocal.Commit, prs []github.PR) int {
	indexBySHA := make(map[string]int, len(commits))
	for i, c := range commits {
		indexBySHA[c.SHA] = i
	}

	associated := make(map[string]bool, len(commits))
	for _, pr := range prs {
		if pr.MergeCommitSHA == "" {
			continue
		}
		idx, ok := indexBySHA[pr.MergeCommitSHA]
		if !ok {
			continue
		}
		n := pr.TotalCommits
		if n < 1 {
			n = 1
		}
		for i := idx; i < len(commits) && i < idx+n; i++ {
			associated[commits[i].SHA] = true
		}
	}

	directPushes := 0
	for _, c := range commits {
		if !associated[c.SHA] {
			directPushes++
		}
	}
	return directPushes
}

func buildGitHubTier(report *Report, in Input) {
	directPushes := countDirectPushes(in.Commits, in.PRs)

	buckets := map[string]int{}
	for _, b := range BucketOrder {
		buckets[b] = 0
	}

	merges := &Merges{DirectPushes: directPushes}
	var findings []Finding

	for _, pr := range in.PRs {
		a := analyzePR(pr)
		merges.Total++
		buckets[a.latencyBucket]++

		var kinds []string
		if !a.meaningfulReview {
			merges.NoReview++
			kinds = append(kinds, FindingNoReview)
		}
		if a.selfMerged {
			merges.SelfMerged++
			kinds = append(kinds, FindingSelfMerged)
		}
		if a.selfApproved {
			merges.SelfApproved++
			kinds = append(kinds, FindingSelfApproved)
		}
		if a.predatesFinalCommit {
			merges.ApprovalPredatesFinalCommit++
			kinds = append(kinds, FindingApprovalPredatesFinalCommit)
		}
		if len(kinds) > 0 {
			findings = append(findings, Finding{PR: pr.Number, URL: pr.URL, Kinds: kinds})
		}
	}

	merges.Total += directPushes
	sort.Slice(findings, func(i, j int) bool { return findings[i].PR < findings[j].PR })

	noMeaningful := merges.NoReview + directPushes
	report.Headline = &Headline{
		NoMeaningfulReview: noMeaningful,
		Total:              merges.Total,
		Share:              round4(safeShare(noMeaningful, merges.Total)),
	}
	report.Merges = merges
	report.ApprovalLatency = bucketSlice(buckets)
	report.Findings = findings
}

func bucketSlice(buckets map[string]int) []LatencyBucket {
	out := make([]LatencyBucket, 0, len(BucketOrder))
	for _, b := range BucketOrder {
		out = append(out, LatencyBucket{Bucket: b, Count: buckets[b]})
	}
	return out
}

func safeShare(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

func round4(f float64) float64 {
	return math.Round(f*10000) / 10000
}
