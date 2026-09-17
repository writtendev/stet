package attest

import (
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// scenario is a fully-mutable description of one packed attestation. Every
// negative test case starts from baseScenario() (a scenario that verifies
// successfully) and changes exactly the field(s) its name describes, so
// each failure is attributable to a single change.
type scenario struct {
	rpID               string
	verifyRPIDOverride string // if non-empty, Statement.RPID uses this; authData's rpIdHash still hashes rpID
	up, uv             bool
	ed                 bool // authData carries an extensions block
	aaguid             [16]byte
	credID             []byte

	alg  int64
	leaf leafSpec

	cdh                    []byte
	cdhOverrideForTransmit []byte // if non-nil, Statement.ClientDataHash uses this; the signature still covers cdh

	tamperAuthDataByteAfterSign int // >=0: flip this byte AFTER signing, in the transmitted authData
	tamperSigByte               bool
	signOverAuthDataOnly        bool
	signOverCDHOnly             bool
	rawSigOverride              []byte // if non-nil, used verbatim instead of signing (for unsupported-alg)

	x5cOverride             [][]byte
	leafIsBundledRoot       bool // use the trust store's own root DER as x5c[0]
	untrustedChain          bool // sign the leaf with a fresh CA that is never added to the trust store
	includeSigningRootInX5C bool // append the (untrusted) signing CA's self-signed cert to x5c
	ecdaaKeyID              []byte

	uvMethods                  []string
	omitFromMetadata           bool
	metadataRootSHA256Override string

	verifyAt time.Time
}

func testAAGUID() [16]byte {
	return [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
}

func baseScenario() scenario {
	return scenario{
		rpID:                        "example.com",
		up:                          true,
		uv:                          false,
		aaguid:                      testAAGUID(),
		credID:                      []byte{0xAA, 0xBB, 0xCC},
		alg:                         algES256,
		leaf:                        leafSpec{keyKind: keyP256, aaguid: testAAGUID(), subject: defaultLeafSubject()},
		cdh:                         mustFixedCDH(0),
		uvMethods:                   []string{"presence_internal", "passcode_external"},
		verifyAt:                    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		tamperAuthDataByteAfterSign: -1,
	}
}

func mustFixedCDH(salt byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i) + salt
	}
	return b
}

// build turns sc into a Statement plus the trust store it should be
// verified against.
func (sc scenario) build(t *testing.T) (Statement, *trustStore) {
	t.Helper()

	trustCA := newTestCA(t)
	signingCA := trustCA
	if sc.untrustedChain {
		signingCA = newTestCA(t)
	}

	leafDER, signer := buildLeaf(t, signingCA, sc.leaf)

	authData := buildAuthData(t, sc.rpID, sc.up, sc.uv, sc.ed, sc.aaguid, sc.credID)

	var signMessage []byte
	switch {
	case sc.signOverAuthDataOnly:
		signMessage = append([]byte(nil), authData...)
	case sc.signOverCDHOnly:
		signMessage = append([]byte(nil), sc.cdh...)
	default:
		signMessage = append(append([]byte(nil), authData...), sc.cdh...)
	}

	var sig []byte
	if sc.rawSigOverride != nil {
		sig = sc.rawSigOverride
	} else {
		sig = signPackedMessage(t, signer, sc.alg, signMessage)
	}
	if sc.tamperSigByte {
		sig = append([]byte(nil), sig...)
		sig[len(sig)-1] ^= 0xFF
	}

	if sc.tamperAuthDataByteAfterSign >= 0 {
		authData = append([]byte(nil), authData...)
		authData[sc.tamperAuthDataByteAfterSign] ^= 0xFF
	}

	x5c := sc.x5cOverride
	if x5c == nil {
		switch {
		case sc.leafIsBundledRoot:
			x5c = [][]byte{trustCA.der}
		default:
			x5c = [][]byte{leafDER}
			if sc.includeSigningRootInX5C {
				x5c = append(x5c, signingCA.der)
			}
		}
	}

	attStmt := marshalTestAttStmt(t, sc.alg, sig, x5c, sc.ecdaaKeyID)

	metaAAGUID := sc.aaguid
	if sc.omitFromMetadata {
		metaAAGUID = [16]byte{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE}
	}
	rootSHA := sha256Hex(trustCA.der)
	if sc.metadataRootSHA256Override != "" {
		rootSHA = sc.metadataRootSHA256Override
	}
	entry := aaguidEntry{
		AAGUID:      formatAAGUID(metaAAGUID),
		Vendor:      "TestVendor",
		Description: "Test Device",
		RootSHA256:  []string{rootSHA},
		UVMethods:   sc.uvMethods,
	}
	trust := trustCA.buildTrustStore(t, aaguidJSONFor(entry))

	rpID := sc.rpID
	if sc.verifyRPIDOverride != "" {
		rpID = sc.verifyRPIDOverride
	}
	cdh := sc.cdh
	if sc.cdhOverrideForTransmit != nil {
		cdh = sc.cdhOverrideForTransmit
	}

	st := Statement{
		Format:         "packed",
		AuthData:       authData,
		AttStmt:        attStmt,
		ClientDataHash: cdh,
		RPID:           rpID,
	}
	return st, trust
}

func (sc scenario) verify(t *testing.T) (Result, error) {
	t.Helper()
	st, trust := sc.build(t)
	return verify(st, Options{At: sc.verifyAt}, trust)
}

func marshalTestAttStmt(t *testing.T, alg int64, sig []byte, x5c [][]byte, ecdaaKeyID []byte) []byte {
	t.Helper()
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	b, err := em.Marshal(packedAttStmt{Alg: alg, Sig: sig, X5C: x5c, ECDAAKeyID: ecdaaKeyID})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
