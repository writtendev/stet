package attest

import (
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
