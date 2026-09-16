//go:build !(cgo && libfido2)

package fido

import (
	"context"
	"fmt"
)

// Backend names the compiled-in authenticator backend. Without the
// libfido2 build tag (or without cgo), no hardware backend is compiled in.
const Backend = "unavailable"

// New returns an Authenticator whose methods all fail with ErrUnsupported.
// Build with cgo enabled and the libfido2 tag to get a working backend:
// install libfido2 (macOS: `brew install libfido2`; Debian/Ubuntu:
// `apt install libfido2-dev`) and build with `-tags libfido2` — the
// Makefile does this automatically when pkg-config finds libfido2.
func New() Authenticator {
	return unsupportedAuthenticator{}
}

type unsupportedAuthenticator struct{}

func (unsupportedAuthenticator) Devices(_ context.Context) ([]DeviceInfo, error) {
	return nil, unsupportedErr()
}

func (unsupportedAuthenticator) MakeCredential(_ context.Context, _ string, _ CredentialRequest) (*Credential, error) {
	return nil, unsupportedErr()
}

func (unsupportedAuthenticator) GetAssertion(_ context.Context, _ string, _ AssertionRequest) (*Assertion, error) {
	return nil, unsupportedErr()
}

func unsupportedErr() error {
	return fmt.Errorf("%w: built without the libfido2 tag (install libfido2 via `brew install libfido2` or `apt install libfido2-dev`, then build with -tags libfido2)", ErrUnsupported)
}
