package attest

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

// TestVerify_MalformedInput covers every case that must return a non-nil
// Go error (not a policy failure) while still leaving Result.Class at
// ClassUnknown -- see doc.go's unknown-by-default contract.
func TestVerify_MalformedInput(t *testing.T) {
	t.Run("truncated authData", func(t *testing.T) {
		sc := baseScenario()
		st, trust := sc.build(t)
		st.AuthData = st.AuthData[:10]
		assertMalformed(t, st, sc.verifyAt, trust)
	})

	t.Run("authData trailing bytes", func(t *testing.T) {
		sc := baseScenario()
		st, trust := sc.build(t)
		st.AuthData = append(st.AuthData, 0x00, 0x01, 0x02)
		assertMalformed(t, st, sc.verifyAt, trust)
	})

	t.Run("AT flag clear", func(t *testing.T) {
		sc := baseScenario()
		st, trust := sc.build(t)
		ad := append([]byte(nil), st.AuthData...)
		ad[32] &^= flagAT
		st.AuthData = ad
		assertMalformed(t, st, sc.verifyAt, trust)
	})

	t.Run("duplicate CBOR map keys in attStmt", func(t *testing.T) {
		sc := baseScenario()
		st, trust := sc.build(t)
		// {"alg": -7, "alg": -8}, two entries in one definite-length map.
		st.AttStmt = []byte{0xA2, 0x63, 'a', 'l', 'g', 0x26, 0x63, 'a', 'l', 'g', 0x27}
		assertMalformed(t, st, sc.verifyAt, trust)
	})

	t.Run("indefinite-length CBOR in attStmt", func(t *testing.T) {
		sc := baseScenario()
		st, trust := sc.build(t)
		// {"alg": -7} as an indefinite-length map (0xBF ... 0xFF).
		st.AttStmt = []byte{0xBF, 0x63, 'a', 'l', 'g', 0x26, 0xFF}
		assertMalformed(t, st, sc.verifyAt, trust)
	})

	t.Run("clientDataHash not 32 bytes", func(t *testing.T) {
		sc := baseScenario()
		st, trust := sc.build(t)
		st.ClientDataHash = st.ClientDataHash[:16]
		assertMalformed(t, st, sc.verifyAt, trust)
	})

	t.Run("zero Options.At", func(t *testing.T) {
		sc := baseScenario()
		st, trust := sc.build(t)
		assertMalformed(t, st, time.Time{}, trust)
	})

	// The COSE credential public key (the value STET-10 will later trust as
	// Result.CredentialKey) must be strictly decoded as a CBOR map, not
	// merely captured as a well-formed opaque item: a duplicate-key map, a
	// bare integer, and a byte string are all well-formed CBOR but none of
	// them is a valid COSE key, and accepting any of them creates a parser
	// differential with whatever later verifies an assertion against the
	// stored bytes.
	coseKeyCases := map[string][]byte{
		"COSE key: duplicate map keys":      {0xA2, 0x01, 0x02, 0x01, 0x03},
		"COSE key: bare integer, not a map": {0x01},
		"COSE key: byte string, not a map":  {0x43, 0x01, 0x02, 0x03},
	}
	for name, badCOSEKey := range coseKeyCases {
		t.Run(name, func(t *testing.T) {
			sc := baseScenario()
			st, trust := sc.build(t)
			st.AuthData = authDataWithRawCOSEKey(t, sc, badCOSEKey)
			assertMalformed(t, st, sc.verifyAt, trust)
		})
	}
}

// authDataWithRawCOSEKey rebuilds sc's authData header (rpIdHash | flags |
// signCount | aaguid | credIdLen | credId) exactly as buildAuthData does,
// then appends rawCOSEKey verbatim instead of a well-formed COSE key item.
// sc must have ed == false (no extensions block after the COSE key).
func authDataWithRawCOSEKey(t *testing.T, sc scenario, rawCOSEKey []byte) []byte {
	t.Helper()
	if sc.ed {
		t.Fatal("authDataWithRawCOSEKey: scenario must not carry an extensions block")
	}

	rpIDHash := sha256.Sum256([]byte(sc.rpID))
	flags := byte(0)
	if sc.up {
		flags |= flagUP
	}
	if sc.uv {
		flags |= flagUV
	}
	flags |= flagAT

	out := make([]byte, 0, 32+1+4+16+2+len(sc.credID)+len(rawCOSEKey))
	out = append(out, rpIDHash[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, 1)
	out = append(out, sc.aaguid[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(sc.credID)))
	out = append(out, sc.credID...)
	out = append(out, rawCOSEKey...)
	return out
}

func assertMalformed(t *testing.T, st Statement, at time.Time, trust *trustStore) {
	t.Helper()
	res, err := verify(st, Options{At: at}, trust)
	if err == nil {
		t.Fatalf("expected an error, got none (result: %+v)", res)
	}
	if res.Class != ClassUnknown {
		t.Errorf("expected ClassUnknown even on error, got %v", res.Class)
	}
	if res.Verified {
		t.Errorf("expected Verified=false on error")
	}
}
