package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthClientID is the GitHub OAuth App client ID used for the
// device-code login flow. It is injected at build time via ldflags
// (-X github.com/writtendev/stet/internal/github.OAuthClientID=...).
// Left empty, device login reports itself as not configured rather than
// failing in a confusing way.
var OAuthClientID string

// deviceScopes is intentionally minimal: read-only access to pull
// requests and reviews on public and private repos the user can see.
const deviceScopes = "repo:status read:org"

// CodeHost is where device.go's endpoints live. Overridable in tests.
type CodeHost struct {
	BaseURL    string // e.g. "https://github.com"
	HTTPClient *http.Client
}

// StderrDeviceFlow implements DeviceFlow against GitHub's real device-code
// endpoints, printing the user code and verification URL to Out.
type StderrDeviceFlow struct {
	Host     CodeHost
	ClientID string
	Out      io.Writer
	Now      func() time.Time
	Sleep    func(context.Context, time.Duration) error
}

// NewDeviceFlow returns a DeviceFlow that writes prompts to out and talks
// to github.com. If OAuthClientID is empty, Token fails immediately with
// a "not configured" error rather than attempting any network call.
func NewDeviceFlow(out io.Writer) DeviceFlow {
	return &StderrDeviceFlow{
		Host:     CodeHost{BaseURL: "https://github.com", HTTPClient: http.DefaultClient},
		ClientID: OAuthClientID,
		Out:      out,
		Now:      time.Now,
		Sleep:    ctxSleep,
	}
}

func ctxSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type accessTokenResponse struct {
	AccessToken      string `json:"access_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Interval         int    `json:"interval"`
}

// Token performs the RFC 8628 device authorization flow: it requests a
// device code, prints the verification URL and user code, then polls for
// the resulting access token.
func (d *StderrDeviceFlow) Token(ctx context.Context) (string, error) {
	if strings.TrimSpace(d.ClientID) == "" {
		return "", errors.New("device login is not configured (no OAuth client id built into this binary); set GH_TOKEN/GITHUB_TOKEN or run `gh auth login` instead")
	}

	client := d.Host.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	dc, err := d.requestDeviceCode(ctx, client)
	if err != nil {
		return "", fmt.Errorf("device login: requesting device code: %w", err)
	}

	if d.Out != nil {
		_, _ = fmt.Fprintf(d.Out, "! To authorize stet, visit %s and enter code %s\n", dc.VerificationURI, dc.UserCode)
	}

	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := d.now().Add(time.Duration(dc.ExpiresIn) * time.Second)

	sleep := d.Sleep
	if sleep == nil {
		sleep = ctxSleep
	}

	for {
		if d.now().After(deadline) {
			return "", errors.New("device login: expired before the user authorized it")
		}
		if err := sleep(ctx, interval); err != nil {
			return "", err
		}

		tok, err := d.pollAccessToken(ctx, client, dc.DeviceCode)
		if err == nil {
			return tok, nil
		}

		switch {
		case errors.Is(err, errAuthorizationPending):
			continue
		case errors.Is(err, errSlowDown):
			interval += 5 * time.Second
			continue
		default:
			return "", fmt.Errorf("device login: %w", err)
		}
	}
}

var (
	errAuthorizationPending = errors.New("authorization_pending")
	errSlowDown             = errors.New("slow_down")
)

func (d *StderrDeviceFlow) requestDeviceCode(ctx context.Context, client *http.Client) (*deviceCodeResponse, error) {
	form := url.Values{
		"client_id": {d.ClientID},
		"scope":     {deviceScopes},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Host.BaseURL+"/login/device/code", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var dc deviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&dc); err != nil {
		return nil, err
	}
	if dc.DeviceCode == "" {
		return nil, fmt.Errorf("unexpected response (status %d)", resp.StatusCode)
	}
	return &dc, nil
}

func (d *StderrDeviceFlow) pollAccessToken(ctx context.Context, client *http.Client, deviceCode string) (string, error) {
	form := url.Values{
		"client_id":   {d.ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Host.BaseURL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	var at accessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&at); err != nil {
		return "", err
	}

	switch at.Error {
	case "":
		if at.AccessToken == "" {
			return "", errors.New("empty access token in response")
		}
		return at.AccessToken, nil
	case "authorization_pending":
		return "", errAuthorizationPending
	case "slow_down":
		return "", errSlowDown
	case "expired_token":
		return "", errors.New("the device code expired")
	case "access_denied":
		return "", errors.New("authorization was denied")
	default:
		desc := at.ErrorDescription
		if desc == "" {
			desc = at.Error
		}
		return "", errors.New(desc)
	}
}

func (d *StderrDeviceFlow) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}
