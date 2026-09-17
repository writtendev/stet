// Package github resolves a GitHub credential locally and reads merged
// pull request review data over GitHub's GraphQL API. The token is
// resolved and used entirely on the local machine: it is read from an
// environment variable, from the `gh` CLI's own credential store, or via
// an RFC 8628 device-code flow, and it is sent to nowhere but the
// configured GitHub API host.
package github

import (
	"context"
	"errors"
	"os"
	"strings"
)

// TokenSource identifies where a resolved token came from, for reporting
// in an audit's output. The token value itself is never included.
type TokenSource string

const (
	SourceEnvGHToken     TokenSource = "env:GH_TOKEN"
	SourceEnvGitHubToken TokenSource = "env:GITHUB_TOKEN"
	SourceGHCLI          TokenSource = "gh"
	SourceDevice         TokenSource = "device"
)

// ErrNoToken is returned by ResolveToken when every resolution strategy is
// unavailable or declined.
var ErrNoToken = errors.New("no GitHub token available: set GH_TOKEN or GITHUB_TOKEN, run `gh auth login`, or run interactively to use device login")

// Env abstracts environment variable lookup so tests never depend on the
// process's real environment.
type Env interface {
	Getenv(key string) string
}

// OSEnv reads from the real process environment.
type OSEnv struct{}

func (OSEnv) Getenv(key string) string { return os.Getenv(key) }

// Runner executes an external command and returns its trimmed stdout.
type Runner interface {
	Output(ctx context.Context, name string, args ...string) (string, error)
}

// DeviceFlow performs an interactive device-code login and returns the
// resulting access token.
type DeviceFlow interface {
	Token(ctx context.Context) (string, error)
}

// ResolveToken tries, in order: GH_TOKEN, GITHUB_TOKEN, `gh auth token`,
// then (only when interactive is true and flow is non-nil) an interactive
// device-code login. It returns the first token found along with where it
// came from.
func ResolveToken(ctx context.Context, env Env, runner Runner, flow DeviceFlow, interactive bool) (string, TokenSource, error) {
	if tok := strings.TrimSpace(env.Getenv("GH_TOKEN")); tok != "" {
		return tok, SourceEnvGHToken, nil
	}
	if tok := strings.TrimSpace(env.Getenv("GITHUB_TOKEN")); tok != "" {
		return tok, SourceEnvGitHubToken, nil
	}
	if runner != nil {
		if out, err := runner.Output(ctx, "gh", "auth", "token", "--hostname", "github.com"); err == nil {
			if tok := strings.TrimSpace(out); tok != "" {
				return tok, SourceGHCLI, nil
			}
		}
	}
	if interactive && flow != nil {
		tok, err := flow.Token(ctx)
		if err != nil {
			return "", "", err
		}
		if tok := strings.TrimSpace(tok); tok != "" {
			return tok, SourceDevice, nil
		}
	}
	return "", "", ErrNoToken
}
