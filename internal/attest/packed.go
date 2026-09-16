package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// COSEAlgorithm identifiers (RFC 9053) for the signature algorithms this
// package accepts in a packed attStmt.
const (
	algES256 int64 = -7
	algES384 int64 = -35
	algEdDSA int64 = -8
	algRS256 int64 = -257
)

// packedDecMode rejects any attStmt map key this struct does not declare.
// ecdaaKeyId is included, even though ECDAA is never accepted, precisely so
// that its presence can be detected and reported as reasonUnsupportedECDAA
// instead of surfacing as an opaque "unknown field" decode error.
var packedDecMode = newStrictDecMode(4, true)

// packedAttStmt is the packed attestation statement CBOR map:
// { "alg": int, "sig": bstr, "x5c": [bstr, ...] (optional), "ecdaaKeyId": bstr (optional) }.
type packedAttStmt struct {
	Alg        int64    `cbor:"alg"`
	Sig        []byte   `cbor:"sig"`
	X5C        [][]byte `cbor:"x5c,omitempty"`
	ECDAAKeyID []byte   `cbor:"ecdaaKeyId,omitempty"`
}

// decodePackedAttStmt strictly decodes raw as a packed attStmt map
// (algorithm step 3): duplicate keys, indefinite-length items, deep
// nesting, and unrecognized keys are all rejected.
func decodePackedAttStmt(raw []byte) (packedAttStmt, error) {
	var stmt packedAttStmt

	rest, err := packedDecMode.UnmarshalFirst(raw, &stmt)
	if err != nil {
		return packedAttStmt{}, fmt.Errorf("attest: decoding packed attStmt: %w", err)
	}
	if len(rest) != 0 {
		return packedAttStmt{}, fmt.Errorf("attest: packed attStmt has %d trailing byte(s)", len(rest))
	}

	return stmt, nil
}

// encodePackedAttStmt canonically re-encodes a packed attStmt map from its
// three primary fields, for StatementFromParts. An empty x5c encodes as an
// absent key (self-attestation), never as an empty CBOR array, matching
// decodePackedAttStmt's own self-attestation check.
func encodePackedAttStmt(alg int64, sig []byte, x5c [][]byte) ([]byte, error) {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	stmt := packedAttStmt{Alg: alg, Sig: sig}
	if len(x5c) > 0 {
		stmt.X5C = x5c
	}

	return em.Marshal(stmt)
}

// verifyPackedSignature verifies sig over authData||clientDataHash using
// leaf's public key and the given COSE algorithm (algorithm step 6). It
// returns a policy reason code ("" on success); it never returns a Go
// error, because every failure here is a policy failure, not malformed
// input.
func verifyPackedSignature(leaf *x509.Certificate, alg int64, sig, authData, clientDataHash []byte) string {
	message := make([]byte, 0, len(authData)+len(clientDataHash))
	message = append(message, authData...)
	message = append(message, clientDataHash...)

	switch alg {
	case algES256:
		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return reasonAlgKeyMismatch
		}
		h := sha256.Sum256(message)
		if !ecdsa.VerifyASN1(pub, h[:], sig) {
			return reasonBadSignature
		}
	case algES384:
		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P384() {
			return reasonAlgKeyMismatch
		}
		h := sha512.Sum384(message)
		if !ecdsa.VerifyASN1(pub, h[:], sig) {
			return reasonBadSignature
		}
	case algEdDSA:
		pub, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			return reasonAlgKeyMismatch
		}
		if !ed25519.Verify(pub, message, sig) {
			return reasonBadSignature
		}
	case algRS256:
		pub, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return reasonAlgKeyMismatch
		}
		h := sha256.Sum256(message)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
			return reasonBadSignature
		}
	default:
		return reasonUnsupportedAlg
	}

	return ""
}
