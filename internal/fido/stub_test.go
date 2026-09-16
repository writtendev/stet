//go:build !(cgo && libfido2)

package fido

import (
	"context"
	"errors"
	"testing"
)

func TestStubBackend(t *testing.T) {
	if Backend != "unavailable" {
		t.Errorf("Backend = %q, want %q", Backend, "unavailable")
	}
}

func TestStubMethodsReturnUnsupported(t *testing.T) {
	a := New()
	ctx := context.Background()

	if _, err := a.Devices(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Devices error = %v, want ErrUnsupported", err)
	}
	if _, err := a.MakeCredential(ctx, "", CredentialRequest{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("MakeCredential error = %v, want ErrUnsupported", err)
	}
	if _, err := a.GetAssertion(ctx, "", AssertionRequest{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("GetAssertion error = %v, want ErrUnsupported", err)
	}
}
