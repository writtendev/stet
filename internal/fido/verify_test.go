package fido

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

// newTestAssertion builds a self-consistent, signed ES256 assertion for
// rpID with the given user-presence/user-verified flags, plus the private
// key that signed it and its PKIX-DER public key.
func newTestAssertion(t *testing.T, rpID string, up, uv bool) (*Assertion, *ecdsa.PrivateKey, []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	var flags byte
	if up {
		flags |= flagUserPresent
	}
	if uv {
		flags |= flagUserVerified
	}
	authData := buildAuthDataForTest(rpID, flags, 1, nil)
	clientDataHash := sha256.Sum256([]byte("clientData"))

	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}

	a := &Assertion{
		AuthData:       authData,
		Signature:      sig,
		CredentialID:   []byte{1, 2, 3},
		ClientDataHash: clientDataHash,
		SignCount:      1,
		Flags:          Flags{UserPresent: up, UserVerified: uv},
	}
	return a, priv, der
}

func TestVerifyAssertionValid(t *testing.T) {
	a, _, der := newTestAssertion(t, "stet", true, false)
	if err := VerifyAssertion(der, ES256, "stet", a, VerifyOptions{}); err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}
}

func TestVerifyAssertionWrongRPID(t *testing.T) {
	a, _, der := newTestAssertion(t, "stet", true, false)
	if err := VerifyAssertion(der, ES256, "not-stet", a, VerifyOptions{}); err == nil {
		t.Fatalf("expected error for a mismatched rpID")
	}
}

func TestVerifyAssertionUserPresenceClear(t *testing.T) {
	a, _, der := newTestAssertion(t, "stet", false, false)
	if err := VerifyAssertion(der, ES256, "stet", a, VerifyOptions{}); err == nil {
		t.Fatalf("expected error when the user-presence flag is clear")
	}
}

func TestVerifyAssertionRequireUVButClear(t *testing.T) {
	a, _, der := newTestAssertion(t, "stet", true, false)
	if err := VerifyAssertion(der, ES256, "stet", a, VerifyOptions{RequireUV: true}); err == nil {
		t.Fatalf("expected error when UV is required but the flag is clear")
	}
}

func TestVerifyAssertionTamperedAuthData(t *testing.T) {
	a, _, der := newTestAssertion(t, "stet", true, false)
	tampered := *a
	tampered.AuthData = append([]byte(nil), a.AuthData...)
	tampered.AuthData[len(tampered.AuthData)-1] ^= 0xFF // flip a signCount byte; leaves rpIdHash intact.

	if err := VerifyAssertion(der, ES256, "stet", &tampered, VerifyOptions{}); err == nil {
		t.Fatalf("expected error for tampered authData")
	}
}

func TestVerifyAssertionTamperedClientDataHash(t *testing.T) {
	a, _, der := newTestAssertion(t, "stet", true, false)
	tampered := *a
	tampered.ClientDataHash[0] ^= 0xFF

	if err := VerifyAssertion(der, ES256, "stet", &tampered, VerifyOptions{}); err == nil {
		t.Fatalf("expected error for a tampered clientDataHash")
	}
}

func TestVerifyAssertionWrongKey(t *testing.T) {
	a, _, _ := newTestAssertion(t, "stet", true, false)

	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherDER, err := x509.MarshalPKIXPublicKey(&otherPriv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	if err := VerifyAssertion(otherDER, ES256, "stet", a, VerifyOptions{}); err == nil {
		t.Fatalf("expected error for the wrong public key")
	}
}

func TestVerifyAssertionAlgorithmMismatch(t *testing.T) {
	a, _, der := newTestAssertion(t, "stet", true, false)
	if err := VerifyAssertion(der, EdDSA, "stet", a, VerifyOptions{}); err == nil {
		t.Fatalf("expected error for an ES256 key verified as EdDSA")
	}
}

// TestVerifyAssertionES256WrongCurve covers the round-1 review finding
// that ES256 (COSE -7) means P-256 specifically: a trust-log entry tagged
// ES256 that actually carries a key on a different curve must be
// rejected as an algorithm/key mismatch, not accepted just because it
// happens to be *ecdsa.PublicKey.
func TestVerifyAssertionES256WrongCurve(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	var flags byte = flagUserPresent
	authData := buildAuthDataForTest("stet", flags, 1, nil)
	clientDataHash := sha256.Sum256([]byte("clientData"))

	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}

	a := &Assertion{
		AuthData:       authData,
		Signature:      sig,
		CredentialID:   []byte{1, 2, 3},
		ClientDataHash: clientDataHash,
		SignCount:      1,
		Flags:          Flags{UserPresent: true},
	}

	if err := VerifyAssertion(der, ES256, "stet", a, VerifyOptions{}); err == nil {
		t.Fatalf("expected error for an ES256-tagged key on the P-384 curve")
	}
}
