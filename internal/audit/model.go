package audit

import "time"

// Window is the time span an audit report covers.
type Window struct {
	Since  time.Time `json:"since"`
	Until  time.Time `json:"until"`
	Months int       `json:"months"`
}

// Sources reports which data tiers went into a report, per the offline
// invariant reconciliation: the git tier always runs; the GitHub tier is
// optional and this says whether it did.
type Sources struct {
	Git                     bool   `json:"git"`
	GitHub                  bool   `json:"github"`
	GitHubUnavailableReason string `json:"github_unavailable_reason,omitempty"`
}

// Headline is the report's single most important number: the share of
// default-branch merges with no meaningful human review. Nil when the
// GitHub tier did not run.
type Headline struct {
	NoMeaningfulReview int     `json:"no_meaningful_review"`
	Total              int     `json:"total"`
	Share              float64 `json:"share"`
}

// Merges breaks the headline down. Nil when the GitHub tier did not run.
type Merges struct {
	Total                       int `json:"total"`
	NoReview                    int `json:"no_review"`
	SelfMerged                  int `json:"self_merged"`
	SelfApproved                int `json:"self_approved"`
	ApprovalPredatesFinalCommit int `json:"approval_predates_final_commit"`
	DirectPushes                int `json:"direct_pushes"`
}

// LatencyBucket is one bucket of the approval-latency histogram. Buckets
// always appear in BucketOrder, even when a count is zero.
type LatencyBucket struct {
	Bucket string `json:"bucket"`
	Count  int    `json:"count"`
}

// BucketOrder is the fixed, stable ordering of approval-latency buckets.
var BucketOrder = []string{"<5m", "5m-1h", "1h-24h", "1d-7d", ">7d", "none"}

// Signatures reports commit-signature coverage over the window.
type Signatures struct {
	Commits  int  `json:"commits"`
	Signed   int  `json:"signed"`
	Verified *int `json:"verified,omitempty"`
}

// MonthShare is one calendar month's bot/agent commit share.
type MonthShare struct {
	Month    string  `json:"month"`
	Commits  int     `json:"commits"`
	BotAgent int     `json:"bot_agent"`
	Share    float64 `json:"share"`
}

// Finding flags one merged PR with one or more of the failure kinds
// below, sorted by PR number ascending.
type Finding struct {
	PR    int      `json:"pr"`
	URL   string   `json:"url"`
	Kinds []string `json:"kinds"`
}

const (
	FindingNoReview                    = "no_review"
	FindingSelfMerged                  = "self_merged"
	FindingSelfApproved                = "self_approved"
	FindingApprovalPredatesFinalCommit = "approval_predates_final_commit"
)

// Report is the complete, deterministic `stet audit` dataset. GitHub-tier
// fields are pointers/omitempty so JSON shows null/absent when that tier
// did not run, rather than a misleading zero.
type Report struct {
	Repo          string  `json:"repo"`
	DefaultBranch string  `json:"default_branch"`
	Window        Window  `json:"window"`
	Sources       Sources `json:"sources"`
	TokenSource   string  `json:"token_source,omitempty"`

	Headline        *Headline       `json:"headline"`
	Merges          *Merges         `json:"merges"`
	ApprovalLatency []LatencyBucket `json:"approval_latency,omitempty"`

	Signatures    Signatures   `json:"signatures"`
	BotAgentShare []MonthShare `json:"bot_agent_share"`

	Findings []Finding `json:"findings,omitempty"`
}
