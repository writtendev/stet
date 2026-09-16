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

const mergedPRsQuery = `
query($owner: String!, $repo: String!, $base: String!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequests(baseRefName: $base, states: MERGED, first: 50, after: $cursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        url
        createdAt
        mergedAt
        author { login __typename }
        mergedBy { login }
        mergeCommit { oid }
        commits(last: 1) { nodes { commit { committedDate } } }
        reviews(first: 100, states: [APPROVED, CHANGES_REQUESTED, COMMENTED]) {
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
	Commits struct {
		Nodes []struct {
			Commit struct {
				CommittedDate string `json:"committedDate"`
			} `json:"commit"`
		} `json:"nodes"`
	} `json:"commits"`
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

// MergedPRs fetches merged pull requests into base, paging until a PR
// merged before since is seen or limit is reached.
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
			pr, err := convertPR(node)
			if err != nil {
				return nil, err
			}
			if pr.MergedAt.Before(since) {
				pageDone = true
				break
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
	if len(node.Commits.Nodes) > 0 {
		finalCommitAt, err = parseTime(node.Commits.Nodes[0].Commit.CommittedDate)
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

	return PR{
		Number:         node.Number,
		URL:            node.URL,
		AuthorLogin:    node.Author.Login,
		AuthorIsBot:    node.Author.Typename == "Bot",
		MergedByLogin:  node.MergedBy.Login,
		MergedAt:       mergedAt,
		CreatedAt:      createdAt,
		MergeCommitSHA: node.MergeCommit.OID,
		FinalCommitAt:  finalCommitAt,
		Reviews:        reviews,
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

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, &RateLimitError{Message: string(respBody)}
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
