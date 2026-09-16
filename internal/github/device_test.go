package github

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeviceFlowNotConfigured(t *testing.T) {
	flow := &StderrDeviceFlow{ClientID: "", Out: &bytes.Buffer{}}
	if _, err := flow.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Errorf("expected a not-configured error, got %v", err)
	}
}

func TestDeviceFlowSuccessAfterPending(t *testing.T) {
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/device/code":
			_ = json.NewEncoder(w).Encode(deviceCodeResponse{
				DeviceCode:      "devcode",
				UserCode:        "USER-CODE",
				VerificationURI: "https://github.com/login/device",
				ExpiresIn:       900,
				Interval:        0,
			})
		case "/login/oauth/access_token":
			polls++
			if polls < 2 {
				_ = json.NewEncoder(w).Encode(accessTokenResponse{Error: "authorization_pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(accessTokenResponse{AccessToken: "gho_devicetoken"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	out := &bytes.Buffer{}
	flow := &StderrDeviceFlow{
		Host:     CodeHost{BaseURL: server.URL, HTTPClient: server.Client()},
		ClientID: "test-client-id",
		Out:      out,
		Now:      time.Now,
		Sleep:    func(ctx context.Context, d time.Duration) error { return nil },
	}

	tok, err := flow.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "gho_devicetoken" {
		t.Errorf("Token = %q", tok)
	}
	if !strings.Contains(out.String(), "USER-CODE") {
		t.Errorf("expected user code printed, got: %s", out.String())
	}
}

func TestDeviceFlowExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/device/code":
			_ = json.NewEncoder(w).Encode(deviceCodeResponse{
				DeviceCode: "devcode", UserCode: "X", VerificationURI: "https://github.com/login/device",
				ExpiresIn: 1, Interval: 0,
			})
		case "/login/oauth/access_token":
			_ = json.NewEncoder(w).Encode(accessTokenResponse{Error: "authorization_pending"})
		}
	}))
	defer server.Close()

	now := time.Now()
	calls := 0
	flow := &StderrDeviceFlow{
		Host:     CodeHost{BaseURL: server.URL, HTTPClient: server.Client()},
		ClientID: "test-client-id",
		Out:      &bytes.Buffer{},
		Now: func() time.Time {
			calls++
			// First call establishes the deadline; subsequent calls jump
			// past it so the loop exits without hanging.
			if calls == 1 {
				return now
			}
			return now.Add(time.Hour)
		},
		Sleep: func(ctx context.Context, d time.Duration) error { return nil },
	}

	if _, err := flow.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected an expiry error, got %v", err)
	}
}

func TestDeviceFlowAccessDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/device/code":
			_ = json.NewEncoder(w).Encode(deviceCodeResponse{
				DeviceCode: "devcode", UserCode: "X", VerificationURI: "https://github.com/login/device",
				ExpiresIn: 900, Interval: 0,
			})
		case "/login/oauth/access_token":
			_ = json.NewEncoder(w).Encode(accessTokenResponse{Error: "access_denied"})
		}
	}))
	defer server.Close()

	flow := &StderrDeviceFlow{
		Host:     CodeHost{BaseURL: server.URL, HTTPClient: server.Client()},
		ClientID: "test-client-id",
		Out:      &bytes.Buffer{},
		Now:      time.Now,
		Sleep:    func(ctx context.Context, d time.Duration) error { return nil },
	}

	if _, err := flow.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected an access_denied error, got %v", err)
	}
}
