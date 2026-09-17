package attest

import (
	"github.com/fxamacker/cbor/v2"
)

// newStrictDecMode builds a CBOR decode mode that forbids the ambiguities a
// hostile or buggy authenticator could exploit: duplicate map keys and
// indefinite-length items are both rejected outright, and nesting is capped
// well below the library default. rejectUnknownFields additionally rejects
// any struct-destined map key that the target struct does not declare; it
// is enabled only for the packed attStmt decode (see packed.go), which is
// the one CBOR item in this package whose exact key set is security
// relevant.
func newStrictDecMode(maxNestedLevels int, rejectUnknownFields bool) cbor.DecMode {
	opts := cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		IndefLength:     cbor.IndefLengthForbidden,
		MaxNestedLevels: maxNestedLevels,
	}
	if rejectUnknownFields {
		opts.ExtraReturnErrors = cbor.ExtraDecErrorUnknownField
	}
	dm, err := opts.DecMode()
	if err != nil {
		// opts above are static and valid; a failure here is a programming
		// error (e.g. maxNestedLevels out of [4, 65535]), not a runtime one.
		panic("attest: invalid cbor decode options: " + err.Error())
	}
	return dm
}

var (
	// objectDecMode decodes the top-level {fmt, authData, attStmt} wrapper.
	objectDecMode = newStrictDecMode(8, false)

	// itemDecMode decodes a single opaque CBOR item out of authData (the
	// COSE credential public key, and the extensions map when present).
	itemDecMode = newStrictDecMode(4, false)
)
