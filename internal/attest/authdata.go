package attest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// authenticatorData flag bits (WebAuthn ยง6.1).
const (
	flagUP byte = 1 << 0 // User Present
	flagUV byte = 1 << 2 // User Verified
	flagAT byte = 1 << 6 // Attested credential data included
	flagED byte = 1 << 7 // Extension data included
)

// authData is the subset of a parsed authenticatorData structure that
// Verify needs. It always describes attested credential data: parseAuthData
// errors if the AT flag is clear.
type authData struct {
	RPIDHash     [32]byte
	Flags        byte
	SignCount    uint32
	AAGUID       [16]byte
	CredentialID []byte
	COSEKey      []byte // raw CBOR bytes of the credential public key item
	UserPresent  bool
	UserVerified bool
}

// parseAuthData parses raw authenticatorData bytes exactly as signed
// (algorithm step 1). It returns an error only for structurally malformed
// input: truncation, a clear AT flag, or trailing bytes after the last
// element authData is defined to contain. Policy checks that depend on
// context the caller has (the expected RPID, whether UP is required) are
// left to the caller.
func parseAuthData(raw []byte) (authData, error) {
	const headerLen = 32 + 1 + 4 // rpIdHash | flags | signCount
	if len(raw) < headerLen {
		return authData{}, fmt.Errorf("attest: authData is %d byte(s), need at least %d", len(raw), headerLen)
	}

	var ad authData
	copy(ad.RPIDHash[:], raw[0:32])
	ad.Flags = raw[32]
	ad.SignCount = binary.BigEndian.Uint32(raw[33:37])
	ad.UserPresent = ad.Flags&flagUP != 0
	ad.UserVerified = ad.Flags&flagUV != 0

	if ad.Flags&flagAT == 0 {
		return authData{}, fmt.Errorf("attest: authData has no attested credential data (AT flag clear)")
	}

	rest := raw[headerLen:]
	const credHeaderLen = 16 + 2 // aaguid | credIdLen
	if len(rest) < credHeaderLen {
		return authData{}, fmt.Errorf("attest: authData truncated in attested credential data header")
	}
	copy(ad.AAGUID[:], rest[0:16])
	credIDLen := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[credHeaderLen:]

	if len(rest) < credIDLen {
		return authData{}, fmt.Errorf("attest: authData truncated in credential id")
	}
	ad.CredentialID = rest[:credIDLen:credIDLen]
	rest = rest[credIDLen:]

	// Exactly one CBOR item: the credential's COSE public key. It is
	// decoded generically (into any, not a fixed map[int]cbor.RawMessage)
	// so that itemDecMode's DupMapKeyEnforcedAPF check applies
	// recursively to every nested map, not just the top level: capturing
	// each value as an undecoded cbor.RawMessage would let a duplicate
	// key buried inside a nested map value pass unnoticed, since RawMessage
	// only slices bytes and never decodes their contents.
	//
	// CBOR null and undefined, decoded into a pointer target (any pointer,
	// including *any), succeed with a zero value and no error -- the same
	// behavior encoding/json gives a pointer -- so they don't surface as a
	// decode error here. Instead they fall out of the map type assertion
	// below: a nil interface is not a map[any]any, so null/undefined are
	// rejected the same way a bare integer or byte string is: "not a map".
	// An empty map (well-formed, but missing the required kty label) is
	// rejected explicitly, since a COSE key with no kty is not a valid COSE
	// key regardless of well-formedness.
	//
	// This package and whatever later verifies an assertion against
	// Result.CredentialKey (STET-10) must agree on which value -2/-3 etc.
	// resolve to; the exact raw bytes are still what's returned, computed
	// from how many bytes decoding the item consumed.
	var coseKeyAny any
	tail, err := itemDecMode.UnmarshalFirst(rest, &coseKeyAny)
	if err != nil {
		return authData{}, fmt.Errorf("attest: authData: decoding COSE key: %w", err)
	}
	coseKeyMap, ok := coseKeyAny.(map[any]any)
	if !ok {
		return authData{}, fmt.Errorf("attest: authData: COSE key is %T, want a CBOR map", coseKeyAny)
	}
	const coseLabelKty = uint64(1)
	if _, hasKty := coseKeyMap[coseLabelKty]; !hasKty {
		return authData{}, fmt.Errorf("attest: authData: COSE key map has no kty (label 1)")
	}
	ad.COSEKey = rest[:len(rest)-len(tail)]
	rest = tail

	if ad.Flags&flagED != 0 {
		var ext cbor.RawMessage
		tail, err = itemDecMode.UnmarshalFirst(rest, &ext)
		if err != nil {
			return authData{}, fmt.Errorf("attest: authData: decoding extensions: %w", err)
		}
		rest = tail
	}

	if len(rest) != 0 {
		return authData{}, fmt.Errorf("attest: authData has %d trailing byte(s)", len(rest))
	}

	return ad, nil
}

// rpIDHashMatches reports whether ad.RPIDHash equals SHA-256(rpID), using a
// constant-time comparison.
func rpIDHashMatches(ad authData, rpID string) bool {
	want := sha256.Sum256([]byte(rpID))
	return subtle.ConstantTimeCompare(ad.RPIDHash[:], want[:]) == 1
}

// formatAAGUID renders b in canonical lowercase 8-4-4-4-12 form.
func formatAAGUID(b [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
