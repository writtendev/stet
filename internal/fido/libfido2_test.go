//go:build cgo && libfido2

package fido

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"
)

func TestLibfido2Backend(t *testing.T) {
	if Backend != "libfido2" {
		t.Errorf("Backend = %q, want %q", Backend, "libfido2")
	}
}

// TestDevicesNoError exercises Devices in CI, where zero authenticators are
// attached: it must return an empty (or short) list, not an error.
func TestDevicesNoError(t *testing.T) {
	a := New()
	devices, err := a.Devices(context.Background())
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	t.Logf("found %d device(s)", len(devices))
}

func TestMakeCredentialNonexistentDeviceMapsToErrNoDevice(t *testing.T) {
	a := New()
	_, err := a.MakeCredential(context.Background(), "/dev/nonexistent-stet-test-device", CredentialRequest{
		RPID:     DefaultRPID,
		UserID:   []byte("user"),
		UserName: "user",
	})
	if !errors.Is(err, ErrNoDevice) {
		t.Fatalf("MakeCredential error = %v, want ErrNoDevice", err)
	}
}

func TestMapErrTable(t *testing.T) {
	// FIDO_ERR_* values, from <fido/err.h>.
	tests := []struct {
		name string
		code int
		want error // nil means mapErr must return nil.
	}{
		{"success", 0x00, nil},
		{"pin required", 0x36, ErrPINRequired},
		{"pin invalid", 0x31, ErrPINInvalid},
		{"action timeout", 0x3a, ErrActionTimeout},
		{"operation denied", 0x27, ErrOperationDenied},
		{"no credentials", 0x2e, ErrNoCredentials},
		{"unsupported algorithm", 0x26, ErrUnsupportedAlgorithm},
		{"keepalive cancel", 0x2d, ErrCancelled},
		{"rx", -2, ErrNoDevice},
		{"tx", -1, ErrNoDevice},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := mapErr(tc.code)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("mapErr(%#x) = %v, want nil", tc.code, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("mapErr(%#x) = %v, want %v", tc.code, err, tc.want)
			}
		})
	}

	if err := mapErr(0x7f); err == nil {
		t.Fatalf("mapErr(unmapped code) = nil, want a non-nil generic error")
	}
}

// TestHardwareDiscoveryAndAssertion exercises the full make-credential /
// get-assertion / verify round trip against a real, physically-present
// authenticator. It is opt-in because it requires a touch: run it with
//
//	STET_FIDO2_HARDWARE=1 go test -tags libfido2 ./internal/fido -run Hardware -v
func TestHardwareDiscoveryAndAssertion(t *testing.T) {
	if os.Getenv("STET_FIDO2_HARDWARE") != "1" {
		t.Skip("set STET_FIDO2_HARDWARE=1 to run against real hardware (requires touching the key)")
	}

	a := New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	devices, err := a.Devices(ctx)
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) == 0 {
		t.Fatal("STET_FIDO2_HARDWARE=1 but no authenticator was found")
	}
	dev := devices[0]

	clientDataHash := sha256.Sum256([]byte("stet hardware test"))
	cred, err := a.MakeCredential(ctx, dev.Path, CredentialRequest{
		RPID:           DefaultRPID,
		RPName:         "stet",
		UserID:         []byte("stet-hardware-test"),
		UserName:       "stet-hardware-test",
		ClientDataHash: clientDataHash,
	})
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	assertion, err := a.GetAssertion(ctx, dev.Path, AssertionRequest{
		RPID:           DefaultRPID,
		ClientDataHash: clientDataHash,
		CredentialIDs:  [][]byte{cred.CredentialID},
	})
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if err := VerifyAssertion(cred.PublicKey, cred.Algorithm, DefaultRPID, assertion, VerifyOptions{}); err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}
}
