package trust

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/writtendev/stet/internal/fido"
	"github.com/writtendev/stet/internal/fido/fidotest"
)

// TestBYOKEndToEnd exercises the full offline bring-your-own-key flow using
// the software authenticator: enroll a key into the trust log, sign a
// content hash, and verify. Then revoke the key and confirm the same
// assertion is rejected, and confirm an assertion from a never-enrolled key
// is rejected too. Nothing here touches the network.
func TestBYOKEndToEnd(t *testing.T) {
	ctx := context.Background()
	soft := fidotest.NewSoft(fidotest.Options{UserPresent: true, UserVerified: true})
	contentHash := sha256.Sum256([]byte("some diff content"))

	cred, err := soft.MakeCredential(ctx, fidotest.DevicePath, fido.CredentialRequest{
		RPID:           fido.DefaultRPID,
		RPName:         "stet",
		UserID:         []byte("enrolled-user"),
		UserName:       "enrolled-user",
		ClientDataHash: contentHash,
	})
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")
	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := log.Add(Entry{
		CredentialID: cred.CredentialID,
		PublicKey:    cred.PublicKey,
		Algorithm:    cred.Algorithm,
		RPID:         fido.DefaultRPID,
		AAGUID:       cred.AAGUID,
		Label:        "enrolled-user's key",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	assertion, err := soft.GetAssertion(ctx, fidotest.DevicePath, fido.AssertionRequest{
		RPID:           fido.DefaultRPID,
		ClientDataHash: contentHash,
		CredentialIDs:  [][]byte{cred.CredentialID},
	})
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}

	if err := set.VerifyAssertion(fido.DefaultRPID, assertion, fido.VerifyOptions{RequireUV: true}); err != nil {
		t.Fatalf("VerifyAssertion (trusted): %v", err)
	}

	// Revoke, reload, and the same assertion must now be rejected.
	revokeLog, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open (revoke): %v", err)
	}
	if err := revokeLog.Revoke(cred.CredentialID, "test revocation"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := revokeLog.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	revokedSet, err := Load(path)
	if err != nil {
		t.Fatalf("Load (after revoke): %v", err)
	}
	if err := revokedSet.VerifyAssertion(fido.DefaultRPID, assertion, fido.VerifyOptions{RequireUV: true}); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("VerifyAssertion (revoked) = %v, want ErrRevokedKey", err)
	}

	// An assertion from a never-enrolled soft key is untrusted.
	otherSoft := fidotest.NewSoft(fidotest.Options{UserPresent: true, UserVerified: true})
	otherCred, err := otherSoft.MakeCredential(ctx, fidotest.DevicePath, fido.CredentialRequest{
		RPID:           fido.DefaultRPID,
		UserID:         []byte("unenrolled-user"),
		UserName:       "unenrolled-user",
		ClientDataHash: contentHash,
	})
	if err != nil {
		t.Fatalf("MakeCredential (unenrolled): %v", err)
	}
	otherAssertion, err := otherSoft.GetAssertion(ctx, fidotest.DevicePath, fido.AssertionRequest{
		RPID:           fido.DefaultRPID,
		ClientDataHash: contentHash,
		CredentialIDs:  [][]byte{otherCred.CredentialID},
	})
	if err != nil {
		t.Fatalf("GetAssertion (unenrolled): %v", err)
	}
	if err := revokedSet.VerifyAssertion(fido.DefaultRPID, otherAssertion, fido.VerifyOptions{}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("VerifyAssertion (untrusted) = %v, want ErrUntrustedKey", err)
	}
}
