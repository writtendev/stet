package audit

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/writtendev/stet/internal/github"
	"github.com/writtendev/stet/internal/gitlocal"
)

func t0(s string) time.Time {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return tm
}

func TestBuildOfflineReport(t *testing.T) {
	now := t0("2025-07-01T00:00:00Z")
	commits := []gitlocal.Commit{
		{SHA: "c1", AuthorName: "Alice", AuthorEmail: "a@example.com", CommittedAt: t0("2025-06-10T00:00:00Z"), SigStatus: "G"},
		{SHA: "c2", AuthorName: "dependabot[bot]", AuthorEmail: "dependabot@users.noreply.github.com", CommittedAt: t0("2025-06-15T00:00:00Z"), SigStatus: "N"},
	}

	report := Build(Input{
		Repo:          "writtendev/stet",
		DefaultBranch: "main",
		Months:        6,
		Commits:       commits,
	}, now)

	if report.Sources.Git != true || report.Sources.GitHub != false {
		t.Errorf("unexpected sources: %+v", report.Sources)
	}
	if report.Headline != nil {
		t.Errorf("expected nil headline offline, got %+v", report.Headline)
	}
	if report.Merges != nil {
		t.Errorf("expected nil merges offline, got %+v", report.Merges)
	}
	if report.Signatures.Commits != 2 || report.Signatures.Signed != 1 {
		t.Errorf("unexpected signatures: %+v", report.Signatures)
	}
	if len(report.BotAgentShare) != 1 {
		t.Fatalf("expected 1 month of bot/agent share, got %+v", report.BotAgentShare)
	}
	m := report.BotAgentShare[0]
	if m.Month != "2025-06" || m.Commits != 2 || m.BotAgent != 1 || m.Share != 0.5 {
		t.Errorf("unexpected month share: %+v", m)
	}
}

func basePR(number int) github.PR {
	return github.PR{
		Number:        number,
		URL:           "https://github.com/writtendev/stet/pull/" + strconv.Itoa(number),
		AuthorLogin:   "author",
		MergedByLogin: "author",
		CreatedAt:     t0("2025-06-01T00:00:00Z"),
		MergedAt:      t0("2025-06-02T00:00:00Z"),
		FinalCommitAt: t0("2025-06-01T12:00:00Z"),
	}
}

func TestAnalyzePRNoReviews(t *testing.T) {
	pr := basePR(1)
	a := analyzePR(pr)
	if a.meaningfulReview {
		t.Error("expected no meaningful review for a PR with zero reviews")
	}
	if a.latencyBucket != "none" {
		t.Errorf("expected 'none' bucket, got %q", a.latencyBucket)
	}
}

func TestAnalyzePRQualifyingApproval(t *testing.T) {
	pr := basePR(2)
	pr.MergedByLogin = "reviewer" // not self-merged
	pr.Reviews = []github.Review{
		{AuthorLogin: "reviewer", State: "APPROVED", SubmittedAt: pr.FinalCommitAt.Add(10 * time.Minute)},
	}
	a := analyzePR(pr)
	if !a.meaningfulReview {
		t.Error("expected meaningful review from a qualifying approver after the final commit")
	}
	if a.latencyBucket != "1h-24h" {
		t.Errorf("expected 1h-24h bucket (created 2025-06-01T00, approved 2025-06-01T12:10), got %q", a.latencyBucket)
	}
	if a.selfMerged {
		t.Error("did not expect self-merged")
	}
}

func TestAnalyzePRSelfApprovalDoesNotCount(t *testing.T) {
	pr := basePR(3)
	pr.Reviews = []github.Review{
		{AuthorLogin: "author", State: "APPROVED", SubmittedAt: pr.FinalCommitAt.Add(time.Minute)},
	}
	a := analyzePR(pr)
	if a.meaningfulReview {
		t.Error("a self-approval must never count as meaningful review")
	}
	if !a.selfApproved {
		t.Error("expected selfApproved to be flagged")
	}
}

func TestAnalyzePRBotApprovalDoesNotCount(t *testing.T) {
	pr := basePR(4)
	pr.MergedByLogin = "someone-else"
	pr.Reviews = []github.Review{
		{AuthorLogin: "some-bot", AuthorIsBot: true, State: "APPROVED", SubmittedAt: pr.FinalCommitAt.Add(time.Minute)},
	}
	a := analyzePR(pr)
	if a.meaningfulReview {
		t.Error("a bot approval must never count as meaningful review")
	}
}

func TestAnalyzePRApprovalExactlyAtCommitTimeCounts(t *testing.T) {
	pr := basePR(5)
	pr.MergedByLogin = "reviewer"
	pr.Reviews = []github.Review{
		{AuthorLogin: "reviewer", State: "APPROVED", SubmittedAt: pr.FinalCommitAt},
	}
	a := analyzePR(pr)
	if !a.meaningfulReview {
		t.Error("an approval exactly at the final commit's time should count (at-or-after)")
	}
	if a.predatesFinalCommit {
		t.Error("an approval exactly at commit time should not be flagged as predating it")
	}
}

func TestAnalyzePRApprovalPredatesFinalCommit(t *testing.T) {
	pr := basePR(6)
	pr.MergedByLogin = "reviewer"
	pr.Reviews = []github.Review{
		{AuthorLogin: "reviewer", State: "APPROVED", SubmittedAt: pr.FinalCommitAt.Add(-time.Hour)},
	}
	a := analyzePR(pr)
	if a.meaningfulReview {
		t.Error("a stale approval before the final commit should not count as meaningful")
	}
	if !a.predatesFinalCommit {
		t.Error("expected predatesFinalCommit to be flagged")
	}
}

func TestAnalyzePRSelfMerged(t *testing.T) {
	pr := basePR(7)
	pr.AuthorLogin = "same"
	pr.MergedByLogin = "SAME" // case-insensitive
	a := analyzePR(pr)
	if !a.selfMerged {
		t.Error("expected case-insensitive self-merge detection")
	}
}

func TestAnalyzePRLatencyUsesFirstQualifyingApproval(t *testing.T) {
	pr := basePR(20)
	pr.MergedByLogin = "reviewer"
	// Approved 2 minutes after opening (2025-06-01T00:02), then a
	// follow-up push moves FinalCommitAt later, and the same reviewer
	// re-approves 3 days after opening. meaningfulReview must key off the
	// latest (it covers the final commit); the latency bucket must key
	// off the earliest, not the latest.
	pr.FinalCommitAt = pr.CreatedAt.Add(2 * 24 * time.Hour)
	pr.Reviews = []github.Review{
		{AuthorLogin: "reviewer", State: "APPROVED", SubmittedAt: pr.CreatedAt.Add(2 * time.Minute)},
		{AuthorLogin: "reviewer", State: "APPROVED", SubmittedAt: pr.CreatedAt.Add(3 * 24 * time.Hour)},
	}
	a := analyzePR(pr)
	if !a.meaningfulReview {
		t.Fatal("expected the later approval (which covers the final commit) to count as meaningful")
	}
	if a.latencyBucket != "<5m" {
		t.Errorf("expected latency bucketed from the first qualifying approval (<5m), got %q", a.latencyBucket)
	}
}

func TestAnalyzePRLatencyMeasuredFromReadyForReviewNotCreatedAt(t *testing.T) {
	pr := basePR(23)
	pr.MergedByLogin = "reviewer"
	// Opened as a draft, sits for 3 days, then marked ready and approved 2
	// minutes later. The brief measures latency from CreatedAt or (when
	// present) ReadyForReviewAt, so this must bucket as <5m, not the
	// 1d-7d it would land in if ReadyForReviewAt were ignored.
	ready := pr.CreatedAt.Add(3 * 24 * time.Hour)
	pr.ReadyForReviewAt = &ready
	pr.FinalCommitAt = ready
	pr.Reviews = []github.Review{
		{AuthorLogin: "reviewer", State: "APPROVED", SubmittedAt: ready.Add(2 * time.Minute)},
	}
	a := analyzePR(pr)
	if !a.meaningfulReview {
		t.Fatal("expected meaningful review")
	}
	if a.latencyBucket != "<5m" {
		t.Errorf("expected latency bucketed from ReadyForReviewAt (<5m), got %q", a.latencyBucket)
	}
}

func TestAnalyzePRCoAuthorApprovalDoesNotCount(t *testing.T) {
	pr := basePR(21)
	pr.MergedByLogin = "someone-else"
	pr.CommitAuthorLogins = []string{"author", "co-author"}
	pr.Reviews = []github.Review{
		{AuthorLogin: "co-author", State: "APPROVED", SubmittedAt: pr.FinalCommitAt.Add(time.Minute)},
	}
	a := analyzePR(pr)
	if a.meaningfulReview {
		t.Error("an approval from a co-author who pushed commits to the branch must not count as independent review")
	}
}

func TestAnalyzePRNonCoAuthorApprovalCounts(t *testing.T) {
	pr := basePR(22)
	pr.MergedByLogin = "reviewer"
	pr.CommitAuthorLogins = []string{"author", "co-author"}
	pr.Reviews = []github.Review{
		{AuthorLogin: "reviewer", State: "APPROVED", SubmittedAt: pr.FinalCommitAt.Add(time.Minute)},
	}
	a := analyzePR(pr)
	if !a.meaningfulReview {
		t.Error("an approval from someone who did not author any commit on the branch should count")
	}
}

func TestCountDirectPushesAssociatesRebaseMergedCommits(t *testing.T) {
	pr := basePR(30)
	pr.MergeCommitSHA = "r3"
	pr.TotalCommits = 3
	// A rebase merge replays each original commit under a new SHA and
	// committer, keeping author identity and message intact -- that
	// identity is what lets countDirectPushes positively associate r2
	// and r1 with this PR even though only r3 is known to GitHub as its
	// MergeCommitSHA.
	pr.Commits = []github.PRCommit{
		{Message: "feat: part one", AuthorEmail: "dev@example.com"},
		{Message: "feat: part two", AuthorEmail: "dev@example.com"},
		{Message: "feat: part three", AuthorEmail: "dev@example.com"},
	}

	// Newest-first, as gitlocal.FirstParentLog returns them: r3 is the
	// commit GitHub reports as MergeCommitSHA (the last rebased commit);
	// r2 and r1 are the other two commits from the same rebase-merged PR
	// and must not be counted as direct pushes even though only r3's SHA
	// is known to GitHub as belonging to this PR.
	commits := []gitlocal.Commit{
		{SHA: "r3", Message: "feat: part three", AuthorEmail: "dev@example.com", CommittedAt: t0("2025-06-03T00:00:00Z")},
		{SHA: "r2", Message: "feat: part two", AuthorEmail: "dev@example.com", CommittedAt: t0("2025-06-02T12:00:00Z")},
		{SHA: "r1", Message: "feat: part one", AuthorEmail: "dev@example.com", CommittedAt: t0("2025-06-02T00:00:00Z")},
		{SHA: "direct1", Message: "chore: unrelated direct push", AuthorEmail: "other@example.com", CommittedAt: t0("2025-06-01T00:00:00Z")},
	}

	n := countDirectPushes(commits, []github.PR{pr})
	if n != 1 {
		t.Errorf("expected only the 1 true direct push, got %d", n)
	}
}

func TestCountDirectPushesCountsUnassociatedMergeCommit(t *testing.T) {
	// A real merge commit pushed straight to the branch (not any fetched
	// PR's merge commit) must count as a direct push, not be exempted
	// just because it has two parents.
	commits := []gitlocal.Commit{
		{SHA: "localmerge", Parents: []string{"p1", "p2"}, CommittedAt: t0("2025-06-01T00:00:00Z")},
	}
	n := countDirectPushes(commits, nil)
	if n != 1 {
		t.Errorf("expected an unassociated merge commit to count as a direct push, got %d", n)
	}
}

func TestCountDirectPushesMergeCommitStrategyClaimsOnlyTheLandedCommit(t *testing.T) {
	// A true "merge commit" strategy PR's landed commit has two parents;
	// its other commits live on the second-parent side, never the base
	// branch's first-parent chain, so nothing beneath it should be
	// claimed even when TotalCommits/Commits says the PR had more than
	// one commit.
	pr := basePR(31)
	pr.MergeCommitSHA = "m1"
	pr.TotalCommits = 2
	pr.Commits = []github.PRCommit{
		{Message: "feat: a", AuthorEmail: "dev@example.com"},
		{Message: "feat: b", AuthorEmail: "dev@example.com"},
	}

	commits := []gitlocal.Commit{
		{SHA: "m1", Parents: []string{"prevtip", "branchtip"}, CommittedAt: t0("2025-06-02T00:00:00Z")},
		{SHA: "direct1", Message: "chore: real direct push", AuthorEmail: "other@example.com", CommittedAt: t0("2025-06-01T00:00:00Z")},
	}

	n := countDirectPushes(commits, []github.PR{pr})
	if n != 1 {
		t.Errorf("expected the 1 direct push beneath the merge commit to still count, got %d", n)
	}
}

func TestCountDirectPushesSquashMergeDoesNotAbsorbCommitBeneathIt(t *testing.T) {
	// A squash-merged PR with many commits on its branch lands as a
	// single first-parent commit whose message is GitHub's synthesized
	// squash message, not any individual original commit's -- so it must
	// not absorb the real direct push sitting directly beneath it just
	// because TotalCommits says the branch had 20 commits.
	pr := basePR(32)
	pr.MergeCommitSHA = "squash1"
	pr.TotalCommits = 20
	pr.Commits = make([]github.PRCommit, 20)
	for i := range pr.Commits {
		pr.Commits[i] = github.PRCommit{
			Message:     fmt.Sprintf("wip commit %d", i),
			AuthorEmail: "dev@example.com",
		}
	}

	commits := []gitlocal.Commit{
		{SHA: "squash1", Message: "feat: squashed PR #32 (#32)", AuthorEmail: "dev@example.com", CommittedAt: t0("2025-06-02T00:00:00Z")},
		{SHA: "direct1", Message: "chore: real direct push right beneath the squash commit", AuthorEmail: "other@example.com", CommittedAt: t0("2025-06-01T00:00:00Z")},
	}

	n := countDirectPushes(commits, []github.PR{pr})
	if n != 1 {
		t.Errorf("expected the direct push beneath the squash commit to still count, got %d", n)
	}
}

func TestBuildGitHubTierHeadlineAndFindings(t *testing.T) {
	now := t0("2025-07-01T00:00:00Z")

	reviewed := basePR(1)
	reviewed.MergedByLogin = "reviewer"
	reviewed.Reviews = []github.Review{
		{AuthorLogin: "reviewer", State: "APPROVED", SubmittedAt: reviewed.FinalCommitAt.Add(time.Minute)},
	}

	unreviewed := basePR(2)

	commits := []gitlocal.Commit{
		{SHA: "direct1", Parents: nil, CommittedAt: t0("2025-06-20T00:00:00Z")}, // direct push, not tied to any PR
	}

	report := Build(Input{
		Repo:            "writtendev/stet",
		DefaultBranch:   "main",
		Months:          6,
		Commits:         commits,
		GitHubAvailable: true,
		TokenSource:     "env:GH_TOKEN",
		PRs:             []github.PR{reviewed, unreviewed},
	}, now)

	if report.Headline == nil {
		t.Fatal("expected a headline when GitHub tier is available")
	}
	// no_review (unreviewed PR) + direct_pushes(1) = 2; total = 2 PRs + 1 direct push = 3
	if report.Headline.NoMeaningfulReview != 2 || report.Headline.Total != 3 {
		t.Errorf("unexpected headline: %+v", report.Headline)
	}
	if report.Headline.Share != round4(2.0/3.0) {
		t.Errorf("unexpected share: %v", report.Headline.Share)
	}
	if report.Merges.DirectPushes != 1 {
		t.Errorf("expected 1 direct push, got %d", report.Merges.DirectPushes)
	}
	if report.Merges.NoReview != 1 {
		t.Errorf("expected 1 PR without review, got %d", report.Merges.NoReview)
	}

	if len(report.Findings) != 1 || report.Findings[0].PR != 2 {
		t.Errorf("expected only PR #2 flagged, got %+v", report.Findings)
	}
}

func TestBuildGitHubTierDirectPushExcludesMergeCommits(t *testing.T) {
	now := t0("2025-07-01T00:00:00Z")
	pr := basePR(1)
	pr.MergeCommitSHA = "merge1"
	pr.MergedByLogin = "reviewer"
	pr.Reviews = []github.Review{
		{AuthorLogin: "reviewer", State: "APPROVED", SubmittedAt: pr.FinalCommitAt.Add(time.Minute)},
	}

	commits := []gitlocal.Commit{
		{SHA: "merge1", Parents: []string{"p1", "p2"}, CommittedAt: t0("2025-06-02T00:00:00Z")},
	}

	report := Build(Input{
		DefaultBranch:   "main",
		Months:          6,
		Commits:         commits,
		GitHubAvailable: true,
		PRs:             []github.PR{pr},
	}, now)

	if report.Merges.DirectPushes != 0 {
		t.Errorf("expected the PR's own merge commit to not count as a direct push, got %d", report.Merges.DirectPushes)
	}
}

func TestBuildZeroDivisionShare(t *testing.T) {
	now := t0("2025-07-01T00:00:00Z")
	report := Build(Input{
		DefaultBranch:   "main",
		Months:          6,
		GitHubAvailable: true,
	}, now)

	if report.Headline.Total != 0 || report.Headline.Share != 0 {
		t.Errorf("expected a zero share (not NaN/Inf) for an empty window, got %+v", report.Headline)
	}
}

func TestBuildEmptyWindow(t *testing.T) {
	now := t0("2025-07-01T00:00:00Z")
	report := Build(Input{DefaultBranch: "main", Months: 6}, now)
	if report.Signatures.Commits != 0 {
		t.Errorf("expected zero commits, got %d", report.Signatures.Commits)
	}
	if len(report.BotAgentShare) != 0 {
		t.Errorf("expected no monthly buckets for an empty window, got %+v", report.BotAgentShare)
	}
}

func TestBucketFor(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{time.Minute, "<5m"},
		{10 * time.Minute, "5m-1h"},
		{2 * time.Hour, "1h-24h"},
		{3 * 24 * time.Hour, "1d-7d"},
		{10 * 24 * time.Hour, ">7d"},
	}
	for _, tc := range cases {
		if got := bucketFor(tc.d); got != tc.want {
			t.Errorf("bucketFor(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
