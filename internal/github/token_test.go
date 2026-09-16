package github

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeEnv map[string]string

func (f fakeEnv) Getenv(key string) string { return f[key] }

type fakeRunner struct {
	out string
	err error
}

func (f fakeRunner) Output(ctx context.Context, name string, args ...string) (string, error) {
	return f.out, f.err
}

type fakeDeviceFlow struct {
	tok string
	err error
}

func (f fakeDeviceFlow) Token(ctx context.Context) (string, error) { return f.tok, f.err }

func TestResolveTokenOrder(t *testing.T) {
	t.Run("GH_TOKEN wins over everything", func(t *testing.T) {
		env := fakeEnv{"GH_TOKEN": "ghtok", "GITHUB_TOKEN": "githubtok"}
		tok, src, err := ResolveToken(context.Background(), env, fakeRunner{out: "ghcli"}, fakeDeviceFlow{tok: "device"}, true)
		if err != nil || tok != "ghtok" || src != SourceEnvGHToken {
			t.Errorf("got (%q, %q, %v)", tok, src, err)
		}
	})

	t.Run("GITHUB_TOKEN used when GH_TOKEN absent", func(t *testing.T) {
		env := fakeEnv{"GITHUB_TOKEN": "githubtok"}
		tok, src, err := ResolveToken(context.Background(), env, fakeRunner{out: "ghcli"}, nil, true)
		if err != nil || tok != "githubtok" || src != SourceEnvGitHubToken {
			t.Errorf("got (%q, %q, %v)", tok, src, err)
		}
	})

	t.Run("gh CLI used when no env vars set", func(t *testing.T) {
		env := fakeEnv{}
		tok, src, err := ResolveToken(context.Background(), env, fakeRunner{out: "ghcli-token\n"}, nil, true)
		if err != nil || tok != "ghcli-token" || src != SourceGHCLI {
			t.Errorf("got (%q, %q, %v)", tok, src, err)
		}
	})

	t.Run("gh CLI failure falls through to device flow", func(t *testing.T) {
		env := fakeEnv{}
		tok, src, err := ResolveToken(context.Background(), env, fakeRunner{err: errors.New("not logged in")}, fakeDeviceFlow{tok: "device-tok"}, true)
		if err != nil || tok != "device-tok" || src != SourceDevice {
			t.Errorf("got (%q, %q, %v)", tok, src, err)
		}
	})

	t.Run("device flow skipped when not interactive", func(t *testing.T) {
		env := fakeEnv{}
		_, _, err := ResolveToken(context.Background(), env, fakeRunner{err: errors.New("no gh")}, fakeDeviceFlow{tok: "device-tok"}, false)
		if !errors.Is(err, ErrNoToken) {
			t.Errorf("expected ErrNoToken, got %v", err)
		}
	})

	t.Run("no token anywhere returns ErrNoToken", func(t *testing.T) {
		env := fakeEnv{}
		_, _, err := ResolveToken(context.Background(), env, fakeRunner{err: errors.New("no gh")}, nil, true)
		if !errors.Is(err, ErrNoToken) {
			t.Errorf("expected ErrNoToken, got %v", err)
		}
	})

	t.Run("device flow error is surfaced", func(t *testing.T) {
		env := fakeEnv{}
		_, _, err := ResolveToken(context.Background(), env, fakeRunner{err: errors.New("no gh")}, fakeDeviceFlow{err: errors.New("access_denied")}, true)
		if err == nil || !strings.Contains(err.Error(), "access_denied") {
			t.Errorf("expected device flow error to surface, got %v", err)
		}
	})

	t.Run("error never contains a token value", func(t *testing.T) {
		env := fakeEnv{}
		_, _, err := ResolveToken(context.Background(), env, fakeRunner{err: errors.New("no gh")}, nil, true)
		if err != nil && strings.Contains(err.Error(), "ghp_") {
			t.Errorf("error message leaked a token-shaped value: %v", err)
		}
	})
}
