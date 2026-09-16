package fido

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

// VerifyOptions controls VerifyAssertion's policy checks beyond the
// signature itself.
type VerifyOptions struct {
	// RequireUV requires the assertion's user-verified flag to be set.
	// User presence is always required, regardless of this setting.
	RequireUV bool
}

// VerifyAssertion checks that a is a valid CTAP2 assertion for rpID, signed
// by the key in publicKeyDER (PKIX DER) under alg.
//
// It checks, in order: that a.AuthData's rpIdHash equals SHA-256(rpID),
// that the user-presence flag is set (always required), that the
// user-verified flag is set when opts.RequireUV is set, and finally the
// signature over authData || clientDataHash — ecdsa.VerifyASN1 on the
// SHA-256 digest for ES256, ed25519.Verify directly for EdDSA.
//
// Signature counter and clone detection are out of scope: this check is
// stateless and makes no assumption about prior assertions.
func VerifyAssertion(publicKeyDER []byte, alg COSEAlgorithm, rpID string, a *Assertion, opts VerifyOptions) error {
	auth, err := ParseAuthData(a.AuthData)
	if err != nil {
		return fmt.Errorf("fido2: verify: %w", err)
	}

	wantRPIDHash := sha256.Sum256([]byte(rpID))
	if auth.RPIDHash != wantRPIDHash {
		return fmt.Errorf("fido2: verify: rpID hash mismatch")
	}

	if !auth.Flags.UserPresent {
		return fmt.Errorf("fido2: verify: user presence flag not set")
	}
	if opts.RequireUV && !auth.Flags.UserVerified {
		return fmt.Errorf("fido2: verify: user verification required but flag not set")
	}

	pub, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return fmt.Errorf("fido2: verify: parse public key: %w", err)
	}

	signed := make([]byte, 0, len(a.AuthData)+len(a.ClientDataHash))
	signed = append(signed, a.AuthData...)
	signed = append(signed, a.ClientDataHash[:]...)

	switch alg {
	case ES256:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("fido2: verify: public key is not ECDSA, cannot verify ES256 signature")
		}
		digest := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(key, digest[:], a.Signature) {
			return fmt.Errorf("fido2: verify: signature invalid")
		}
	case EdDSA:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("fido2: verify: public key is not Ed25519, cannot verify EdDSA signature")
		}
		if !ed25519.Verify(key, signed, a.Signature) {
			return fmt.Errorf("fido2: verify: signature invalid")
		}
	default:
		return fmt.Errorf("%w: COSE algorithm %d", ErrUnsupportedAlgorithm, alg)
	}

	return nil
}
