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
		if IsBotOrAgentCommit(c.AuthorName, c.AuthorEmail, c.Trailers) {
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
	var latestApproval, latestQualifying *github.Review

	for i := range pr.Reviews {
		rv := &pr.Reviews[i]
		if rv.State != "APPROVED" {
			continue
		}
		if latestApproval == nil || rv.SubmittedAt.After(latestApproval.SubmittedAt) {
			latestApproval = rv
		}
		if isQualifyingApprover(*rv, pr) {
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
		a.latencyBucket = bucketFor(latestQualifying.SubmittedAt.Sub(start))
	} else {
		a.latencyBucket = "none"
	}

	return a
}

func isQualifyingApprover(rv github.Review, pr github.PR) bool {
	if IsBotOrAgentLogin(rv.AuthorLogin, rv.AuthorIsBot) {
		return false
	}
	return !strings.EqualFold(rv.AuthorLogin, pr.AuthorLogin)
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

func buildGitHubTier(report *Report, in Input) {
	mergeCommits := make(map[string]bool, len(in.PRs))
	for _, pr := range in.PRs {
		if pr.MergeCommitSHA != "" {
			mergeCommits[pr.MergeCommitSHA] = true
		}
	}

	directPushes := 0
	for _, c := range in.Commits {
		if !c.IsMerge() && !mergeCommits[c.SHA] {
			directPushes++
		}
	}

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
