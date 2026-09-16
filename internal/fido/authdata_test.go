package fido

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"testing"
)

func buildAuthDataForTest(rpID string, flags byte, signCount uint32, attested []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 37+len(attested))
	buf = append(buf, rpHash[:]...)
	buf = append(buf, flags)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	buf = append(buf, sc[:]...)
	buf = append(buf, attested...)
	return buf
}

func attestedCredDataForTest(aaguid [16]byte, credID, pubKey []byte) []byte {
	buf := make([]byte, 0, 16+2+len(credID)+len(pubKey))
	buf = append(buf, aaguid[:]...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(credID)))
	buf = append(buf, l[:]...)
	buf = append(buf, credID...)
	buf = append(buf, pubKey...)
	return buf
}

func TestParseAuthDataNoAttestedCredential(t *testing.T) {
	authData := buildAuthDataForTest("stet", flagUserPresent|flagUserVerified, 7, nil)

	got, err := ParseAuthData(authData)
	if err != nil {
		t.Fatalf("ParseAuthData: %v", err)
	}

	wantHash := sha256.Sum256([]byte("stet"))
	if got.RPIDHash != wantHash {
		t.Errorf("RPIDHash = %x, want %x", got.RPIDHash, wantHash)
	}
	if !got.Flags.UserPresent || !got.Flags.UserVerified || got.Flags.AttestedCredentialData {
		t.Errorf("unexpected flags: %+v", got.Flags)
	}
	if got.SignCount != 7 {
		t.Errorf("SignCount = %d, want 7", got.SignCount)
	}
	if len(got.CredentialID) != 0 || len(got.CredentialPublicKey) != 0 {
		t.Errorf("expected no attested credential data, got CredentialID=%x CredentialPublicKey=%x", got.CredentialID, got.CredentialPublicKey)
	}
}

func TestParseAuthDataWithAttestedCredential(t *testing.T) {
	aaguid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	credID := []byte{0xde, 0xad, 0xbe, 0xef}
	pubKey := []byte{0xa5, 0x01, 0x02, 0x03, 0x26} // arbitrary bytes; ParseAuthData does not decode the key.
	attested := attestedCredDataForTest(aaguid, credID, pubKey)
	authData := buildAuthDataForTest("stet", flagUserPresent|flagAttestedCredentialData, 1, attested)

	got, err := ParseAuthData(authData)
	if err != nil {
		t.Fatalf("ParseAuthData: %v", err)
	}
	if !got.Flags.AttestedCredentialData {
		t.Fatalf("expected AttestedCredentialData flag to be set")
	}
	if got.AAGUID != aaguid {
		t.Errorf("AAGUID = %x, want %x", got.AAGUID, aaguid)
	}
	if !bytes.Equal(got.CredentialID, credID) {
		t.Errorf("CredentialID = %x, want %x", got.CredentialID, credID)
	}
	if !bytes.Equal(got.CredentialPublicKey, pubKey) {
		t.Errorf("CredentialPublicKey = %x, want %x", got.CredentialPublicKey, pubKey)
	}
}

func TestParseAuthDataRejectsTruncatedBuffer(t *testing.T) {
	if _, err := ParseAuthData(make([]byte, 10)); err == nil {
		t.Fatalf("expected error for a truncated buffer")
	}
}

func TestParseAuthDataRejectsBadCredentialIDLength(t *testing.T) {
	var aaguid [16]byte
	attested := attestedCredDataForTest(aaguid, nil, nil)
	// Claim a 100-byte credential ID follows, though nothing does.
	binary.BigEndian.PutUint16(attested[16:18], 100)
	authData := buildAuthDataForTest("stet", flagUserPresent|flagAttestedCredentialData, 0, attested)

	if _, err := ParseAuthData(authData); err == nil {
		t.Fatalf("expected error for a credential ID length exceeding the buffer")
	}
}

func TestParseAuthDataRejectsExtensionFlag(t *testing.T) {
	authData := buildAuthDataForTest("stet", flagUserPresent|flagExtensionData, 0, nil)
	if _, err := ParseAuthData(authData); err == nil {
		t.Fatalf("expected error for a set extension-data flag")
	}
}

func TestUnwrapCBORByteStringShortLength(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5} // len < 24: encoded directly in the header byte.
	header := append([]byte{0x40 | byte(len(payload))}, payload...)

	got, err := unwrapCBORByteString(header)
	if err != nil {
		t.Fatalf("unwrapCBORByteString: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %x, want %x", got, payload)
	}
}

func TestUnwrapCBORByteStringOneByteLength(t *testing.T) {
	payload := make([]byte, 30) // len > 23: needs the 1-byte length form (additional info 24).
	for i := range payload {
		payload[i] = byte(i)
	}
	header := append([]byte{0x58, byte(len(payload))}, payload...)

	got, err := unwrapCBORByteString(header)
	if err != nil {
		t.Fatalf("unwrapCBORByteString: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %x, want %x", got, payload)
	}
}

func TestUnwrapCBORByteStringTwoByteLength(t *testing.T) {
	payload := make([]byte, 300) // len > 255: needs the 2-byte length form (additional info 25).
	for i := range payload {
		payload[i] = byte(i)
	}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	header := append([]byte{0x59}, l[:]...)
	header = append(header, payload...)

	got, err := unwrapCBORByteString(header)
	if err != nil {
		t.Fatalf("unwrapCBORByteString: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %x, want %x", got, payload)
	}
}

func TestUnwrapCBORByteStringRejectsWrongMajorType(t *testing.T) {
	if _, err := unwrapCBORByteString([]byte{0x00}); err == nil {
		t.Fatalf("expected error for a non-byte-string major type")
	}
}

func TestUnwrapCBORByteStringRejectsTruncated(t *testing.T) {
	if _, err := unwrapCBORByteString([]byte{0x58}); err == nil {
		t.Fatalf("expected error for a truncated length header")
	}
	if _, err := unwrapCBORByteString([]byte{0x45, 0x01, 0x02}); err == nil {
		t.Fatalf("expected error when declared length exceeds available bytes")
	}
}

func TestPublicKeyToPKIXES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	raw := make([]byte, 64)
	priv.X.FillBytes(raw[:32])
	priv.Y.FillBytes(raw[32:])

	der, err := publicKeyToPKIX(ES256, raw)
	if err != nil {
		t.Fatalf("publicKeyToPKIX: %v", err)
	}

	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PublicKey", pub)
	}
	if ecPub.X.Cmp(priv.X) != 0 || ecPub.Y.Cmp(priv.Y) != 0 {
		t.Errorf("round-tripped key does not match original")
	}
}

func TestPublicKeyToPKIXEdDSA(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	der, err := publicKeyToPKIX(EdDSA, pub)
	if err != nil {
		t.Fatalf("publicKeyToPKIX: %v", err)
	}

	got, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	edPub, ok := got.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("got %T, want ed25519.PublicKey", got)
	}
	if !bytes.Equal(edPub, pub) {
		t.Errorf("round-tripped key does not match original")
	}
}

func TestPublicKeyToPKIXRejectsBadLength(t *testing.T) {
	if _, err := publicKeyToPKIX(ES256, make([]byte, 10)); err == nil {
		t.Fatalf("expected error for a short ES256 key")
	}
	if _, err := publicKeyToPKIX(EdDSA, make([]byte, 10)); err == nil {
		t.Fatalf("expected error for a short EdDSA key")
	}
}

func TestPublicKeyToPKIXRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := publicKeyToPKIX(COSEAlgorithm(999), make([]byte, 64)); err == nil {
		t.Fatalf("expected error for an unknown COSE algorithm")
	}
}
