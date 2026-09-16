package fidotest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/writtendev/stet/internal/fido"
)

func TestSoftMakeCredentialGetAssertionVerify(t *testing.T) {
	soft := NewSoft(Options{UserPresent: true, UserVerified: true})
	ctx := context.Background()
	clientDataHash := sha256.Sum256([]byte("test client data"))

	cred, err := soft.MakeCredential(ctx, DevicePath, fido.CredentialRequest{
		RPID:           fido.DefaultRPID,
		RPName:         "stet",
		UserID:         []byte("user-1"),
		UserName:       "user-1",
		ClientDataHash: clientDataHash,
	})
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	credAuthData, err := fido.ParseAuthData(cred.AuthData)
	if err != nil {
		t.Fatalf("ParseAuthData(credential): %v", err)
	}

	assertion, err := soft.GetAssertion(ctx, DevicePath, fido.AssertionRequest{
		RPID:           fido.DefaultRPID,
		ClientDataHash: clientDataHash,
		CredentialIDs:  [][]byte{cred.CredentialID},
	})
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if err := fido.VerifyAssertion(cred.PublicKey, cred.Algorithm, fido.DefaultRPID, assertion, fido.VerifyOptions{RequireUV: true}); err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}

	assertAuthData, err := fido.ParseAuthData(assertion.AuthData)
	if err != nil {
		t.Fatalf("ParseAuthData(assertion): %v", err)
	}
	if !bytes.Equal(assertion.CredentialID, cred.CredentialID) {
		t.Errorf("assertion CredentialID = %x, want %x", assertion.CredentialID, cred.CredentialID)
	}
	if credAuthData.AAGUID != cred.AAGUID {
		t.Errorf("ParseAuthData AAGUID = %x, want Credential.AAGUID = %x", credAuthData.AAGUID, cred.AAGUID)
	}
	if !bytes.Equal(credAuthData.CredentialID, cred.CredentialID) {
		t.Errorf("ParseAuthData CredentialID = %x, want Credential.CredentialID = %x", credAuthData.CredentialID, cred.CredentialID)
	}
	if assertAuthData.RPIDHash != credAuthData.RPIDHash {
		t.Errorf("assertion rpIdHash differs from credential rpIdHash")
	}
}

func TestSoftCancelledContext(t *testing.T) {
	soft := NewSoft(Options{UserPresent: true})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := soft.Devices(ctx); !errors.Is(err, fido.ErrCancelled) {
		t.Errorf("Devices error = %v, want ErrCancelled", err)
	}
	if _, err := soft.MakeCredential(ctx, DevicePath, fido.CredentialRequest{}); !errors.Is(err, fido.ErrCancelled) {
		t.Errorf("MakeCredential error = %v, want ErrCancelled", err)
	}
	if _, err := soft.GetAssertion(ctx, DevicePath, fido.AssertionRequest{}); !errors.Is(err, fido.ErrCancelled) {
		t.Errorf("GetAssertion error = %v, want ErrCancelled", err)
	}
}

func TestSoftRequireUVWithoutPINGivesErrPINRequired(t *testing.T) {
	soft := NewSoft(Options{UserPresent: true})
	ctx := context.Background()

	_, err := soft.MakeCredential(ctx, DevicePath, fido.CredentialRequest{
		RPID:      fido.DefaultRPID,
		UserID:    []byte("user-1"),
		UserName:  "user-1",
		RequireUV: true,
	})
	if !errors.Is(err, fido.ErrPINRequired) {
		t.Fatalf("MakeCredential error = %v, want ErrPINRequired", err)
	}
}

func TestSoftNoDevicesGivesErrNoDevice(t *testing.T) {
	soft := NewSoft(Options{NoDevices: true})
	ctx := context.Background()

	devices, err := soft.Devices(ctx)
	if err != nil {
		t.Fatalf("Devices: %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("Devices = %v, want none", devices)
	}

	_, err = soft.MakeCredential(ctx, DevicePath, fido.CredentialRequest{RPID: fido.DefaultRPID})
	if !errors.Is(err, fido.ErrNoDevice) {
		t.Fatalf("MakeCredential error = %v, want ErrNoDevice", err)
	}
	_, err = soft.GetAssertion(ctx, DevicePath, fido.AssertionRequest{RPID: fido.DefaultRPID, CredentialIDs: [][]byte{{1}}})
	if !errors.Is(err, fido.ErrNoDevice) {
		t.Fatalf("GetAssertion error = %v, want ErrNoDevice", err)
	}
}

func TestSoftFailWith(t *testing.T) {
	wantErr := errors.New("boom")
	soft := NewSoft(Options{UserPresent: true, FailWith: wantErr})
	ctx := context.Background()

	if _, err := soft.Devices(ctx); !errors.Is(err, wantErr) {
		t.Errorf("Devices error = %v, want %v", err, wantErr)
	}
	if _, err := soft.MakeCredential(ctx, DevicePath, fido.CredentialRequest{RPID: fido.DefaultRPID}); !errors.Is(err, wantErr) {
		t.Errorf("MakeCredential error = %v, want %v", err, wantErr)
	}
}

func TestSoftWrongPINGivesErrPINInvalid(t *testing.T) {
	soft := NewSoft(Options{UserPresent: true, PIN: "1234"})
	ctx := context.Background()

	_, err := soft.MakeCredential(ctx, DevicePath, fido.CredentialRequest{
		RPID:     fido.DefaultRPID,
		UserID:   []byte("user-1"),
		UserName: "user-1",
		PIN:      "0000",
	})
	if !errors.Is(err, fido.ErrPINInvalid) {
		t.Fatalf("MakeCredential error = %v, want ErrPINInvalid", err)
	}
}

func TestSoftDeterministicWithFixedRand(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 1<<20)

	soft1 := NewSoft(Options{UserPresent: true, Rand: bytes.NewReader(seed)})
	soft2 := NewSoft(Options{UserPresent: true, Rand: bytes.NewReader(seed)})
	ctx := context.Background()
	clientDataHash := sha256.Sum256([]byte("determinism"))

	cred1, err := soft1.MakeCredential(ctx, DevicePath, fido.CredentialRequest{
		RPID: fido.DefaultRPID, UserID: []byte("u"), UserName: "u", ClientDataHash: clientDataHash,
	})
	if err != nil {
		t.Fatalf("MakeCredential(soft1): %v", err)
	}
	cred2, err := soft2.MakeCredential(ctx, DevicePath, fido.CredentialRequest{
		RPID: fido.DefaultRPID, UserID: []byte("u"), UserName: "u", ClientDataHash: clientDataHash,
	})
	if err != nil {
		t.Fatalf("MakeCredential(soft2): %v", err)
	}

	if !bytes.Equal(cred1.CredentialID, cred2.CredentialID) {
		t.Errorf("CredentialID differs across identical Rand seeds: %x != %x", cred1.CredentialID, cred2.CredentialID)
	}
	if !bytes.Equal(cred1.PublicKey, cred2.PublicKey) {
		t.Errorf("PublicKey differs across identical Rand seeds")
	}
}

// TestSoftEmptyRPIDDefaults covers the round-1 review finding that
// DefaultRPID was documented as "used when none is given" but never
// actually applied: an empty RPID on both the credential and assertion
// requests must behave exactly as fido.DefaultRPID would, so a caller
// that omits RPID and later verifies against fido.DefaultRPID succeeds.
func TestSoftEmptyRPIDDefaults(t *testing.T) {
	soft := NewSoft(Options{UserPresent: true})
	ctx := context.Background()
	clientDataHash := sha256.Sum256([]byte("empty rpid test"))

	cred, err := soft.MakeCredential(ctx, DevicePath, fido.CredentialRequest{
		UserID:         []byte("user-1"),
		UserName:       "user-1",
		ClientDataHash: clientDataHash,
	})
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	assertion, err := soft.GetAssertion(ctx, DevicePath, fido.AssertionRequest{
		ClientDataHash: clientDataHash,
		CredentialIDs:  [][]byte{cred.CredentialID},
	})
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if err := fido.VerifyAssertion(cred.PublicKey, cred.Algorithm, fido.DefaultRPID, assertion, fido.VerifyOptions{}); err != nil {
		t.Fatalf("VerifyAssertion against fido.DefaultRPID after an empty RPID request: %v", err)
	}
}

func TestSoftNoMatchingCredentialGivesErrNoCredentials(t *testing.T) {
	soft := NewSoft(Options{UserPresent: true})
	ctx := context.Background()

	_, err := soft.GetAssertion(ctx, DevicePath, fido.AssertionRequest{
		RPID:          fido.DefaultRPID,
		CredentialIDs: [][]byte{{0xff, 0xff}},
	})
	if !errors.Is(err, fido.ErrNoCredentials) {
		t.Fatalf("GetAssertion error = %v, want ErrNoCredentials", err)
	}
}
