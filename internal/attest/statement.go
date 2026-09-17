package attest

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Statement is the adapter-independent input to Verify: the raw bytes of a
// single make-credential attestation, exactly as produced by the
// authenticator and exactly as signed. Callers construct a Statement with
// ParseAttestationObject or StatementFromParts rather than filling this
// struct directly, so that AttStmt always holds a well-formed CBOR map.
type Statement struct {
	// Format is the attestation statement format identifier as reported by
	// the authenticator: "packed", "none", "fido-u2f", ... Only "packed"
	// can reach a hardware Class; every other value classifies as unknown.
	Format string

	// AuthData is the raw authenticatorData bytes exactly as signed: NOT
	// CBOR-wrapped. libfido2 callers must use fido_cred_authdata_raw_ptr,
	// not fido_cred_authdata_ptr.
	AuthData []byte

	// AttStmt is the raw CBOR encoding of the attStmt map.
	AttStmt []byte

	// ClientDataHash is the exactly-32-byte hash passed to make-credential.
	ClientDataHash []byte

	// RPID is the relying party id used at make-credential time. authData's
	// rpIdHash must equal SHA-256(RPID).
	RPID string
}

// rawAttestationObject mirrors the WebAuthn AttestationObject CBOR map:
// { "fmt": tstr, "authData": bstr, "attStmt": map }.
type rawAttestationObject struct {
	Fmt      string          `cbor:"fmt"`
	AuthData []byte          `cbor:"authData"`
	AttStmt  cbor.RawMessage `cbor:"attStmt"`
}

// ParseAttestationObject decodes a full CBOR {fmt, authData, attStmt}
// attestation object, as produced by a WebAuthn navigator.credentials.create
// call, into a Statement. clientDataHash is the SHA-256 of the client data
// JSON that accompanied the ceremony; rpID is the relying party id used at
// that ceremony.
func ParseAttestationObject(attObj []byte, clientDataHash []byte, rpID string) (Statement, error) {
	var raw rawAttestationObject

	rest, err := objectDecMode.UnmarshalFirst(attObj, &raw)
	if err != nil {
		return Statement{}, fmt.Errorf("attest: parsing attestation object: %w", err)
	}
	if len(rest) != 0 {
		return Statement{}, fmt.Errorf("attest: attestation object has %d trailing byte(s)", len(rest))
	}

	return Statement{
		Format:         raw.Fmt,
		AuthData:       raw.AuthData,
		AttStmt:        []byte(raw.AttStmt),
		ClientDataHash: clientDataHash,
		RPID:           rpID,
	}, nil
}

// StatementFromParts builds a Statement from libfido2's split accessors
// (fido_cred_fmt, fido_cred_authdata_raw_ptr, fido_cred_sig_ptr,
// fido_cred_x5c_ptr / the x5c list, and the credential's COSE algorithm),
// for authenticator bindings that never assemble a combined attestation
// object. It re-encodes a canonical attStmt CBOR map from the given fields
// so that the rest of this package can treat both constructors identically.
//
// An empty x5c (nil or zero-length) encodes as an absent x5c key, matching
// how Verify's self-attestation check (packed.go) expects a self-attested
// statement to look.
func StatementFromParts(format string, authDataRaw []byte, alg int64, sig []byte, x5c [][]byte, clientDataHash []byte, rpID string) (Statement, error) {
	attStmt, err := encodePackedAttStmt(alg, sig, x5c)
	if err != nil {
		return Statement{}, fmt.Errorf("attest: encoding attStmt: %w", err)
	}

	return Statement{
		Format:         format,
		AuthData:       authDataRaw,
		AttStmt:        attStmt,
		ClientDataHash: clientDataHash,
		RPID:           rpID,
	}, nil
}
