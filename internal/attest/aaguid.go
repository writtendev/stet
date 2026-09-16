package attest

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
)

// oidFIDOGenCEAAGUID is the id-fido-gen-ce-aaguid certificate extension OID
// (FIDO Alliance arc 1.3.6.1.4.1.45724.1.1.4) that binds a packed
// attestation certificate to the AAGUID it attests for.
var oidFIDOGenCEAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// checkAAGUIDExtension implements algorithm step 7: it finds the
// id-fido-gen-ce-aaguid extension on leaf, requires it to be non-critical,
// requires its content to decode as a DER OCTET STRING of exactly 16 bytes
// with no trailing data, and requires that value to equal authDataAAGUID.
// It returns a policy reason code, or "" if every check passes.
func checkAAGUIDExtension(leaf *x509.Certificate, authDataAAGUID [16]byte) string {
	found := false
	var value []byte
	critical := false

	for i := range leaf.Extensions {
		if leaf.Extensions[i].Id.Equal(oidFIDOGenCEAAGUID) {
			found = true
			critical = leaf.Extensions[i].Critical
			value = leaf.Extensions[i].Value
			break
		}
	}

	if !found {
		return reasonAAGUIDUnbound
	}
	if critical {
		return reasonAAGUIDExtCritical
	}

	var content []byte
	rest, err := asn1.Unmarshal(value, &content)
	if err != nil || len(rest) != 0 || len(content) != 16 {
		return reasonAAGUIDExtMalformed
	}

	if subtle.ConstantTimeCompare(content, authDataAAGUID[:]) != 1 {
		return reasonAAGUIDMismatch
	}
	if authDataAAGUID == ([16]byte{}) {
		return reasonAAGUIDZero
	}

	return ""
}
