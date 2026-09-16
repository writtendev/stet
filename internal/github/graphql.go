package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GraphQLClient implements Client against the real GitHub GraphQL API. It
// sends its bearer token only to BaseURL.
type GraphQLClient struct {
	Token      string
	BaseURL    string // default https://api.github.com/graphql
	HTTPClient *http.Client
}

// NewGraphQLClient returns a Client that authenticates with token against
// the production GitHub API.
func NewGraphQLClient(token string) *GraphQLClient {
	return &GraphQLClient{
		Token:      token,
		BaseURL:    "https://api.github.com/graphql",
		HTTPClient: http.DefaultClient,
	}
}

// RateLimitError is returned when GitHub reports the request was rejected
// for exceeding a rate limit.
type RateLimitError struct {
	Message string
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("github: rate limited: %s", e.Message)
}

// mergedPRsQuery's commitAuthors alias bounds how many commits (last:
// 100) and authors per commit (first: 10) it samples to build
// CommitAuthorLogins and PR.Commits. last (not first) keeps the newest
// 100: countDirectPushes walks backwards from the landed commit, so the
// commits immediately beneath it in the first-parent chain are the PR's
// newest ones, and those are the ones that must be in PR.Commits for the
// walk to keep matching instead of stopping early. That is a generous
// cap for ordinary PRs, not a hard guarantee for enormous ones; missing
// an author only means a rare, very-early co-author isn't excluded from
// qualifying approvers, and a PR with more than 100 commits leaks its
// oldest replayed commits as phantom direct pushes past the cap.
//
// reviews requests only APPROVED (the only state compute.go reads) with
// last: 100, not first: 100 over every state: fetching CHANGES_REQUESTED
// and COMMENTED too counted every inline-comment reply and review-bot
// pass toward the same 100-review cap, so a busy PR's actual final
// approval -- past review #100 in submission order -- was never
// fetched. Restricting to APPROVED alone drops that noise, and last
// (not first) keeps the newest ones when a PR genuinely has more than
// 100 real approvals.
const mergedPRsQuery = `
query($owner: String!, $repo: String!, $base: String!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequests(baseRefName: $base, states: MERGED, first: 50, after: $cursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        url
        createdAt
        updatedAt
        mergedAt
        author { login __typename }
        mergedBy { login }
        mergeCommit { oid }
        finalCommit: commits(last: 1) { nodes { commit { committedDate } } }
        commitAuthors: commits(last: 100) {
          totalCount
          nodes {
            commit {
              message
              author { name email }
              authors(first: 10) { nodes { user { login } } }
            }
          }
        }
        reviews(last: 100, states: [APPROVED]) {
          nodes { author { login __typename } state submittedAt }
        }
      }
    }
  }
}`

type graphqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type graphqlError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

type prNode struct {
	Number    int    `json:"number"`
	URL       string `json:"url"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
	MergedAt  string `json:"mergedAt"`
	Author    struct {
		Login    string `json:"login"`
		Typename string `json:"__typename"`
	} `json:"author"`
	MergedBy struct {
		Login string `json:"login"`
	} `json:"mergedBy"`
	MergeCommit struct {
		OID string `json:"oid"`
	} `json:"mergeCommit"`
	FinalCommit struct {
		Nodes []struct {
			Commit struct {
				CommittedDate string `json:"committedDate"`
			} `json:"commit"`
		} `json:"nodes"`
	} `json:"finalCommit"`
	CommitAuthors struct {
		TotalCount int `json:"totalCount"`
		Nodes      []struct {
			Commit struct {
				Message string `json:"message"`
				Author  struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"author"`
				Authors struct {
					Nodes []struct {
						User struct {
							Login string `json:"login"`
						} `json:"user"`
					} `json:"nodes"`
				} `json:"authors"`
			} `json:"commit"`
		} `json:"nodes"`
	} `json:"commitAuthors"`
	Reviews struct {
		Nodes []struct {
			Author struct {
				Login    string `json:"login"`
				Typename string `json:"__typename"`
			} `json:"author"`
			State       string `json:"state"`
			SubmittedAt string `json:"submittedAt"`
		} `json:"nodes"`
	} `json:"reviews"`
}

type mergedPRsResponse struct {
	Data struct {
		Repository struct {
			PullRequests struct {
				PageInfo struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Nodes []prNode `json:"nodes"`
			} `json:"pullRequests"`
		} `json:"repository"`
	} `json:"data"`
	Errors []graphqlError `json:"errors"`
}

// MergedPRs fetches merged pull requests into base, paging until a page
// is exhausted, limit is reached, or a PR is seen whose updatedAt is
// before since.
//
// Pages are ordered UPDATED_AT DESC, not MERGED_AT DESC (GitHub's API
// offers no merged-date ordering), and updatedAt and mergedAt are not the
// same clock: a PR merged long ago can be updated today by a comment, a
// label, or a bot edit, which sorts it to the top of page 1 even though
// it merged well outside the window. So paging only stops once a PR's
// updatedAt itself falls before since -- which is a safe bound, since
// updatedAt is always >= mergedAt, so every PR after it in this
// updatedAt-DESC order also has mergedAt < since. A PR seen before that
// point whose own mergedAt is before since is skipped, not treated as
// the end of the window.
func (c *GraphQLClient) MergedPRs(ctx context.Context, owner, repo, base string, since time.Time, limit int) ([]PR, error) {
	var results []PR
	var cursor *string

	for {
		vars := map[string]any{"owner": owner, "repo": repo, "base": base}
		if cursor != nil {
			vars["cursor"] = *cursor
		}

		resp, err := c.do(ctx, graphqlRequest{Query: mergedPRsQuery, Variables: vars})
		if err != nil {
			return nil, err
		}
		if len(resp.Errors) > 0 {
			return nil, fmt.Errorf("github: graphql error: %s", resp.Errors[0].Message)
		}

		pageDone := false
		for _, node := range resp.Data.Repository.PullRequests.Nodes {
			updatedAt, err := parseTime(node.UpdatedAt)
			if err != nil {
				return nil, fmt.Errorf("github: parsing PR #%d updatedAt: %w", node.Number, err)
			}
			if updatedAt.Before(since) {
				// Safe to stop: sorted UPDATED_AT DESC, and updatedAt >=
				// mergedAt, so every remaining PR merged before since too.
				pageDone = true
				break
			}

			pr, err := convertPR(node)
			if err != nil {
				return nil, err
			}
			if pr.MergedAt.Before(since) {
				// Updated recently but merged before since: outside the
				// window, but does not end paging -- an in-window PR can
				// still appear later on this or a following page.
				continue
			}

			results = append(results, pr)
			if len(results) >= limit {
				return results, nil
			}
		}

		page := resp.Data.Repository.PullRequests.PageInfo
		if pageDone || !page.HasNextPage {
			return results, nil
		}
		cursor = &page.EndCursor
	}
}

func convertPR(node prNode) (PR, error) {
	createdAt, err := parseTime(node.CreatedAt)
	if err != nil {
		return PR{}, fmt.Errorf("github: parsing PR #%d createdAt: %w", node.Number, err)
	}
	mergedAt, err := parseTime(node.MergedAt)
	if err != nil {
		return PR{}, fmt.Errorf("github: parsing PR #%d mergedAt: %w", node.Number, err)
	}

	var finalCommitAt time.Time
	if len(node.FinalCommit.Nodes) > 0 {
		finalCommitAt, err = parseTime(node.FinalCommit.Nodes[0].Commit.CommittedDate)
		if err != nil {
			return PR{}, fmt.Errorf("github: parsing PR #%d final commit date: %w", node.Number, err)
		}
	}

	reviews := make([]Review, 0, len(node.Reviews.Nodes))
	for _, rv := range node.Reviews.Nodes {
		submittedAt, err := parseTime(rv.SubmittedAt)
		if err != nil {
			return PR{}, fmt.Errorf("github: parsing PR #%d review submittedAt: %w", node.Number, err)
		}
		reviews = append(reviews, Review{
			AuthorLogin: rv.Author.Login,
			AuthorIsBot: rv.Author.Typename == "Bot",
			State:       rv.State,
			SubmittedAt: submittedAt,
		})
	}

	seen := map[string]bool{}
	var commitAuthorLogins []string
	commits := make([]PRCommit, 0, len(node.CommitAuthors.Nodes))
	for _, cn := range node.CommitAuthors.Nodes {
		commits = append(commits, PRCommit{
			Message:     cn.Commit.Message,
			AuthorName:  cn.Commit.Author.Name,
			AuthorEmail: cn.Commit.Author.Email,
		})
		for _, an := range cn.Commit.Authors.Nodes {
			login := an.User.Login
			if login == "" || seen[login] {
				continue
			}
			seen[login] = true
			commitAuthorLogins = append(commitAuthorLogins, login)
		}
	}

	return PR{
		Number:             node.Number,
		URL:                node.URL,
		AuthorLogin:        node.Author.Login,
		AuthorIsBot:        node.Author.Typename == "Bot",
		MergedByLogin:      node.MergedBy.Login,
		MergedAt:           mergedAt,
		CreatedAt:          createdAt,
		MergeCommitSHA:     node.MergeCommit.OID,
		TotalCommits:       node.CommitAuthors.TotalCount,
		Commits:            commits,
		CommitAuthorLogins: commitAuthorLogins,
		FinalCommitAt:      finalCommitAt,
		Reviews:            reviews,
	}, nil
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

func (c *GraphQLClient) do(ctx context.Context, body graphqlRequest) (*mergedPRsResponse, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "bearer "+c.Token)

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &RateLimitError{Message: string(respBody)}
	}
	if resp.StatusCode == http.StatusForbidden {
		if isRateLimitResponse(resp.Header) {
			return nil, &RateLimitError{Message: string(respBody)}
		}
		// A plain 403 also covers SAML SSO enforcement and insufficient
		// token scope, neither of which a rate-limit wait will fix, so
		// only the signals GitHub actually documents for rate limiting
		// (a zeroed remaining count, or a Retry-After) are treated as one.
		return nil, fmt.Errorf("github: forbidden (status 403): %s", string(respBody))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var out mergedPRsResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("github: decoding response: %w", err)
	}
	for _, e := range out.Errors {
		if e.Type == "RATE_LIMITED" {
			return nil, &RateLimitError{Message: e.Message}
		}
	}
	return &out, nil
}

// isRateLimitResponse reports whether response headers indicate a 403 was
// actually a rate limit: GitHub sets X-RateLimit-Remaining: 0 for a
// primary rate limit, and a Retry-After header for a secondary one.
func isRateLimitResponse(h http.Header) bool {
	if h.Get("Retry-After") != "" {
		return true
	}
	return h.Get("X-RateLimit-Remaining") == "0"
}
