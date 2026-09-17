package fido

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"fmt"
)

// AuthData is the decoded form of a CTAP2 authenticatorData structure.
//
// Extension data is not supported: ParseAuthData rejects a buffer whose
// extension-data flag is set, since without a CBOR decoder there is no way
// to know where extension data ends. The credential public key, when
// present, is returned as the raw undecoded CBOR COSE-key bytes; nothing in
// this package decodes it further (the libfido2 backend gets a decoded
// public key independently, from libfido2's own pubkey accessor, not from
// authData).
type AuthData struct {
	RPIDHash  [32]byte
	Flags     Flags
	SignCount uint32

	// AAGUID, CredentialID and CredentialPublicKey are set only when
	// Flags.AttestedCredentialData is true.
	AAGUID              [16]byte
	CredentialID        []byte
	CredentialPublicKey []byte
}

const (
	flagUserPresent            = 1 << 0
	flagUserVerified           = 1 << 2
	flagAttestedCredentialData = 1 << 6
	flagExtensionData          = 1 << 7
)

// ParseAuthData decodes a raw (already CBOR-byte-string-unwrapped)
// authenticatorData buffer: rpIdHash (32 bytes), flags (1 byte), signCount
// (4 bytes, big-endian), and, when the attested-credential-data flag is set,
// aaguid (16 bytes), a 2-byte big-endian credential ID length, the
// credential ID, and the remaining bytes as the raw COSE credential public
// key.
func ParseAuthData(b []byte) (AuthData, error) {
	const headerLen = 32 + 1 + 4
	if len(b) < headerLen {
		return AuthData{}, fmt.Errorf("fido2: authData too short: got %d bytes, need at least %d", len(b), headerLen)
	}

	var out AuthData
	copy(out.RPIDHash[:], b[0:32])

	flagByte := b[32]
	out.Flags = Flags{
		UserPresent:            flagByte&flagUserPresent != 0,
		UserVerified:           flagByte&flagUserVerified != 0,
		AttestedCredentialData: flagByte&flagAttestedCredentialData != 0,
	}
	hasExtensions := flagByte&flagExtensionData != 0

	out.SignCount = binary.BigEndian.Uint32(b[33:37])
	rest := b[37:]

	if hasExtensions {
		return AuthData{}, fmt.Errorf("fido2: authData extension data is not supported")
	}

	if !out.Flags.AttestedCredentialData {
		if len(rest) != 0 {
			return AuthData{}, fmt.Errorf("fido2: authData has %d unexpected trailing bytes", len(rest))
		}
		return out, nil
	}

	const attestedCredHeaderLen = 16 + 2
	if len(rest) < attestedCredHeaderLen {
		return AuthData{}, fmt.Errorf("fido2: authData attested credential data too short: got %d bytes, need at least %d", len(rest), attestedCredHeaderLen)
	}
	copy(out.AAGUID[:], rest[0:16])
	credIDLen := binary.BigEndian.Uint16(rest[16:18])
	rest = rest[18:]

	if int(credIDLen) > len(rest) {
		return AuthData{}, fmt.Errorf("fido2: authData credential ID length %d exceeds remaining %d bytes", credIDLen, len(rest))
	}
	out.CredentialID = append([]byte(nil), rest[:credIDLen]...)
	rest = rest[credIDLen:]

	if len(rest) == 0 {
		return AuthData{}, fmt.Errorf("fido2: authData is missing the credential public key")
	}
	out.CredentialPublicKey = append([]byte(nil), rest...)

	return out, nil
}

// unwrapCBORByteString strips a single CBOR major-type-2 (byte string)
// header from b and returns the enclosed bytes.
//
// libfido2 1.14 (the version this repo builds and tests against) returns
// authData from fido_cred_authdata_ptr and fido_assert_authdata_ptr wrapped
// in exactly this header. fido_assert_authdata_raw_ptr, which would return
// authData already unwrapped, was added after 1.14 and is deliberately not
// used here.
func unwrapCBORByteString(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("fido2: empty CBOR byte string")
	}

	major := b[0] >> 5
	if major != 2 {
		return nil, fmt.Errorf("fido2: expected CBOR major type 2 (byte string), got major type %d", major)
	}
	info := b[0] & 0x1f
	b = b[1:]

	var length uint64
	switch {
	case info < 24:
		length = uint64(info)
	case info == 24:
		if len(b) < 1 {
			return nil, fmt.Errorf("fido2: truncated CBOR byte string 1-byte length")
		}
		length = uint64(b[0])
		b = b[1:]
	case info == 25:
		if len(b) < 2 {
			return nil, fmt.Errorf("fido2: truncated CBOR byte string 2-byte length")
		}
		length = uint64(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	case info == 26:
		if len(b) < 4 {
			return nil, fmt.Errorf("fido2: truncated CBOR byte string 4-byte length")
		}
		length = uint64(binary.BigEndian.Uint32(b[:4]))
		b = b[4:]
	case info == 27:
		if len(b) < 8 {
			return nil, fmt.Errorf("fido2: truncated CBOR byte string 8-byte length")
		}
		length = binary.BigEndian.Uint64(b[:8])
		b = b[8:]
	default:
		return nil, fmt.Errorf("fido2: unsupported CBOR byte string length encoding (additional info %d)", info)
	}

	if length > uint64(len(b)) {
		return nil, fmt.Errorf("fido2: CBOR byte string declares %d bytes, only %d available", length, len(b))
	}
	return b[:length], nil
}

// publicKeyToPKIX converts libfido2's raw public key material — 64-byte
// x||y for ES256, or 32 raw bytes for EdDSA — into PKIX DER.
func publicKeyToPKIX(alg COSEAlgorithm, raw []byte) ([]byte, error) {
	switch alg {
	case ES256:
		if len(raw) != 64 {
			return nil, fmt.Errorf("fido2: ES256 public key must be 64 bytes (x||y), got %d", len(raw))
		}
		// Uncompressed SEC1 point format (0x04 || x || y). ecdh.NewPublicKey
		// validates the point is actually on P-256, which replaces the
		// deprecated elliptic.Curve.IsOnCurve check; x509 knows how to
		// marshal a NIST-curve *ecdh.PublicKey as an ordinary PKIX EC key.
		point := make([]byte, 0, 65)
		point = append(point, 0x04)
		point = append(point, raw...)
		pub, err := ecdh.P256().NewPublicKey(point)
		if err != nil {
			return nil, fmt.Errorf("fido2: ES256 public key is not a valid point on P-256: %w", err)
		}
		return x509.MarshalPKIXPublicKey(pub)
	case EdDSA:
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("fido2: EdDSA public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
		}
		pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(pub, raw)
		return x509.MarshalPKIXPublicKey(pub)
	default:
		return nil, fmt.Errorf("%w: COSE algorithm %d", ErrUnsupportedAlgorithm, alg)
	}
}
