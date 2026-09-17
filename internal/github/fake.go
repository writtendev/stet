package github

import (
	"context"
	"time"
)

// FakeClient is an in-memory Client for tests. It never makes a network
// call.
type FakeClient struct {
	PRs   []PR
	Err   error
	Calls int
}

// MergedPRs returns PRs from FakeClient.PRs at or after since, honoring
// limit, or FakeClient.Err if set.
func (f *FakeClient) MergedPRs(ctx context.Context, owner, repo, base string, since time.Time, limit int) ([]PR, error) {
	f.Calls++
	if f.Err != nil {
		return nil, f.Err
	}
	var out []PR
	for _, pr := range f.PRs {
		if pr.MergedAt.Before(since) {
			continue
		}
		out = append(out, pr)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// FailingClient always fails a test if MergedPRs is invoked; useful for
// asserting that --offline mode never reaches out to GitHub.
type FailingClient struct {
	Fail func(msg string)
}

func (f *FailingClient) MergedPRs(ctx context.Context, owner, repo, base string, since time.Time, limit int) ([]PR, error) {
	if f.Fail != nil {
		f.Fail("MergedPRs was called but this client should never be invoked")
	}
	return nil, nil
}
