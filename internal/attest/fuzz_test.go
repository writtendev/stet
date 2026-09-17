package attest

import (
	"os"
	"testing"
	"time"
)

// FuzzVerify fuzzes Verify over (authData, attStmt) with format, rpID, and
// clientDataHash held fixed, seeded from the real captured fixtures. It
// asserts two invariants that must hold for any input whatsoever: Verify
// never panics, and a non-Verified Result is never reported as a hardware
// class (doc.go's unknown-by-default contract).
func FuzzVerify(f *testing.F) {
	for _, name := range []string{"yubikey_es256", "yubikey_eddsa"} {
		authData, err := readTestdataForFuzz(name + "_authdata.bin")
		if err != nil {
			f.Fatal(err)
		}
		attStmt, err := readTestdataForFuzz(name + "_attstmt.cbor")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(authData, attStmt)
	}
	// A couple of structurally-degenerate seeds, so the corpus doesn't
	// depend solely on well-formed captures.
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x00}, []byte{0xA0})

	rpID := "localhost"
	cdh := make([]byte, 32)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, authData, attStmt []byte) {
		st := Statement{
			Format:         "packed",
			AuthData:       authData,
			AttStmt:        attStmt,
			ClientDataHash: cdh,
			RPID:           rpID,
		}

		res, _ := Verify(st, Options{At: at})
		if !res.Verified && res.Class != ClassUnknown {
			t.Fatalf("unverified result classified as %v (reasons=%v)", res.Class, res.Reasons)
		}
		if res.Verified && res.Class == ClassUnknown {
			t.Fatalf("verified result classified as unknown")
		}
	})
}

func readTestdataForFuzz(name string) ([]byte, error) {
	return os.ReadFile("testdata/" + name)
}
