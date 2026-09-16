package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loadFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return string(b)
}

// pagedServer serves fixture pages in sequence, one response per request,
// and records every Authorization header it sees.
func pagedServer(t *testing.T, pages []string) (*httptest.Server, *[]string) {
	t.Helper()
	var authHeaders []string
	i := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		if i >= len(pages) {
			t.Fatalf("unexpected extra request %d", i+1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, pages[i])
		i++
	}))
	return server, &authHeaders
}

func TestGraphQLMergedPRsPagination(t *testing.T) {
	page1 := loadFixture(t, "merged_prs_page1.json")
	page2 := loadFixture(t, "merged_prs_page2.json")

	server, auth := pagedServer(t, []string{page1, page2})
	defer server.Close()

	client := &GraphQLClient{Token: "test-token", BaseURL: server.URL, HTTPClient: server.Client()}

	prs, err := client.MergedPRs(context.Background(), "writtendev", "stet", "main", time.Time{}, 100)
	if err != nil {
		t.Fatalf("MergedPRs: %v", err)
	}
	if len(prs) != 3 {
		t.Fatalf("expected 3 PRs across both pages, got %d", len(prs))
	}
	if prs[0].Number != 10 || prs[2].Number != 8 {
		t.Errorf("unexpected PR numbers: %+v", []int{prs[0].Number, prs[1].Number, prs[2].Number})
	}
	for _, h := range *auth {
		if h != "bearer test-token" {
			t.Errorf("expected bearer auth header, got %q", h)
		}
	}
}

func TestGraphQLMergedPRsWindowCutoff(t *testing.T) {
	page1 := loadFixture(t, "merged_prs_page1.json")
	server, _ := pagedServer(t, []string{page1})
	defer server.Close()

	client := &GraphQLClient{Token: "tok", BaseURL: server.URL, HTTPClient: server.Client()}

	// Fixture PR #9 merged 2025-06-01; cutting off after that date should
	// stop before page 2 is ever requested.
	since := time.Date(2025, 6, 2, 0, 0, 0, 0, time.UTC)
	prs, err := client.MergedPRs(context.Background(), "writtendev", "stet", "main", since, 100)
	if err != nil {
		t.Fatalf("MergedPRs: %v", err)
	}
	if len(prs) != 1 || prs[0].Number != 10 {
		t.Errorf("expected only PR #10 after cutoff, got %+v", prs)
	}
}

func TestGraphQLMergedPRsLimit(t *testing.T) {
	page1 := loadFixture(t, "merged_prs_page1.json")
	server, _ := pagedServer(t, []string{page1})
	defer server.Close()

	client := &GraphQLClient{Token: "tok", BaseURL: server.URL, HTTPClient: server.Client()}

	prs, err := client.MergedPRs(context.Background(), "writtendev", "stet", "main", time.Time{}, 1)
	if err != nil {
		t.Fatalf("MergedPRs: %v", err)
	}
	if len(prs) != 1 {
		t.Errorf("expected limit to cap results at 1, got %d", len(prs))
	}
}

func TestGraphQLMergedPRsCommitAuthorsAndTotalCount(t *testing.T) {
	page1 := loadFixture(t, "merged_prs_page1.json")
	server, _ := pagedServer(t, []string{page1})
	defer server.Close()

	client := &GraphQLClient{Token: "tok", BaseURL: server.URL, HTTPClient: server.Client()}

	prs, err := client.MergedPRs(context.Background(), "writtendev", "stet", "main", time.Time{}, 1)
	if err != nil {
		t.Fatalf("MergedPRs: %v", err)
	}
	if len(prs) != 1 {
		t.Fatalf("expected 1 PR, got %d", len(prs))
	}
	pr := prs[0]
	if pr.TotalCommits != 1 {
		t.Errorf("expected TotalCommits 1, got %d", pr.TotalCommits)
	}
	if len(pr.CommitAuthorLogins) != 1 || pr.CommitAuthorLogins[0] != "alice" {
		t.Errorf("expected CommitAuthorLogins [alice], got %+v", pr.CommitAuthorLogins)
	}
}

func TestGraphQLMergedPRsCommitAuthorsQueryFetchesNewestCommits(t *testing.T) {
	var capturedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		capturedBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, loadFixture(t, "merged_prs_page1.json"))
	}))
	defer server.Close()

	client := &GraphQLClient{Token: "tok", BaseURL: server.URL, HTTPClient: server.Client()}
	if _, err := client.MergedPRs(context.Background(), "writtendev", "stet", "main", time.Time{}, 100); err != nil {
		t.Fatalf("MergedPRs: %v", err)
	}

	// countDirectPushes walks backwards from a PR'''s landed commit, so the
	// commits it needs to positively match are the PR'''s newest ones --
	// those immediately beneath the landing point in the first-parent
	// chain. Fetching the oldest 100 (first: 100) instead leaks every
	// commit past the cap on a large rebase-merged PR as a phantom direct
	// push; last (not first) keeps the newest ones.
	if !strings.Contains(capturedBody, "commitAuthors: commits(last: 100)") {
		t.Errorf("expected the commitAuthors query to request the newest 100 commits, got: %s", capturedBody)
	}
}

func TestGraphQLMergedPRsReviewsQueryFetchesOnlyLatestApproved(t *testing.T) {
	var capturedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		capturedBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, loadFixture(t, "merged_prs_page1.json"))
	}))
	defer server.Close()

	client := &GraphQLClient{Token: "tok", BaseURL: server.URL, HTTPClient: server.Client()}
	if _, err := client.MergedPRs(context.Background(), "writtendev", "stet", "main", time.Time{}, 100); err != nil {
		t.Fatalf("MergedPRs: %v", err)
	}

	// On a busy PR, fetching CHANGES_REQUESTED and COMMENTED reviews too
	// counted every inline-comment reply and review-bot pass toward the
	// same 100-review cap, so the real final APPROVED review -- the only
	// state analyzePR reads -- could fall past node #100 and never be
	// fetched. Requesting only APPROVED, with last (not first) to keep
	// the newest ones, fixes that.
	if !strings.Contains(capturedBody, "reviews(last: 100, states: [APPROVED])") {
		t.Errorf("expected the reviews query to request only the newest 100 APPROVED reviews, got: %s", capturedBody)
	}
	if strings.Contains(capturedBody, "CHANGES_REQUESTED") || strings.Contains(capturedBody, "COMMENTED") {
		t.Errorf("expected CHANGES_REQUESTED/COMMENTED reviews (unused by analyzePR, and only noise against the review cap) to no longer be fetched, got: %s", capturedBody)
	}
}

func TestGraphQLRateLimitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message": "API rate limit exceeded"}`)
	}))
	defer server.Close()

	client := &GraphQLClient{Token: "tok", BaseURL: server.URL, HTTPClient: server.Client()}
	_, err := client.MergedPRs(context.Background(), "writtendev", "stet", "main", time.Time{}, 100)
	if err == nil {
		t.Fatal("expected an error")
	}
	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Errorf("expected a *RateLimitError, got %T: %v", err, err)
	}
}

func TestGraphQLRateLimitRetryAfterHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message": "You have exceeded a secondary rate limit"}`)
	}))
	defer server.Close()

	client := &GraphQLClient{Token: "tok", BaseURL: server.URL, HTTPClient: server.Client()}
	_, err := client.MergedPRs(context.Background(), "writtendev", "stet", "main", time.Time{}, 100)
	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Errorf("expected a *RateLimitError for a Retry-After 403, got %T: %v", err, err)
	}
}

func TestGraphQLForbiddenWithoutRateLimitHeadersIsPlainError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message": "Resource protected by organization SAML enforcement"}`)
	}))
	defer server.Close()

	client := &GraphQLClient{Token: "tok", BaseURL: server.URL, HTTPClient: server.Client()}
	_, err := client.MergedPRs(context.Background(), "writtendev", "stet", "main", time.Time{}, 100)
	if err == nil {
		t.Fatal("expected an error")
	}
	var rle *RateLimitError
	if errors.As(err, &rle) {
		t.Fatal("a SAML-enforcement 403 with no rate-limit headers must not be reported as a rate limit")
	}
	if !strings.Contains(err.Error(), "SAML enforcement") {
		t.Errorf("expected the underlying message to surface, got %v", err)
	}
}

func TestGraphQLMergedPRsSkipsStaleUpdatedPRWithoutStoppingPagination(t *testing.T) {
	page1 := loadFixture(t, "merged_prs_stale_update_page1.json")
	page2 := loadFixture(t, "merged_prs_stale_update_page2.json")

	server, _ := pagedServer(t, []string{page1, page2})
	defer server.Close()

	client := &GraphQLClient{Token: "tok", BaseURL: server.URL, HTTPClient: server.Client()}

	// PR #50 merged long ago (2023) but was updated recently (2025-06-10),
	// so UPDATED_AT DESC sorts it onto page 1 ahead of PR #40, which
	// merged inside the window. A PR merged outside the window must be
	// skipped, not treated as the end of the window, so page 2 must still
	// be fetched and PR #40 must still be collected.
	since := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	prs, err := client.MergedPRs(context.Background(), "writtendev", "stet", "main", since, 100)
	if err != nil {
		t.Fatalf("MergedPRs: %v", err)
	}
	if len(prs) != 1 || prs[0].Number != 40 {
		t.Fatalf("expected only in-window PR #40, got %+v", prs)
	}
}

func TestGraphQLErrorsField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"errors": []map[string]string{{"message": "Could not resolve to a Repository"}},
		})
	}))
	defer server.Close()

	client := &GraphQLClient{Token: "tok", BaseURL: server.URL, HTTPClient: server.Client()}
	_, err := client.MergedPRs(context.Background(), "nope", "nope", "main", time.Time{}, 100)
	if err == nil || !strings.Contains(err.Error(), "Could not resolve") {
		t.Errorf("expected graphql error to surface, got %v", err)
	}
}
