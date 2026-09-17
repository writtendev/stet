package attest

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestInvariant_ZeroResultIsUnknown(t *testing.T) {
	var res Result
	if res.Class != ClassUnknown {
		t.Errorf("zero-value Result.Class = %v, want ClassUnknown", res.Class)
	}
	if res.Verified {
		t.Errorf("zero-value Result.Verified = true, want false")
	}
}

func TestInvariant_ClassJSONRoundTrip(t *testing.T) {
	for _, c := range []Class{ClassUnknown, ClassHardwareTouch, ClassHardwarePIN, ClassHardwareBiometric} {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal %v: %v", c, err)
		}

		var got Class
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if got != c {
			t.Errorf("round trip: %v -> %s -> %v", c, b, got)
		}
	}

	want := map[Class]string{
		ClassUnknown:           `"unknown"`,
		ClassHardwareTouch:     `"hardware+touch"`,
		ClassHardwarePIN:       `"hardware+PIN"`,
		ClassHardwareBiometric: `"hardware+biometric"`,
	}
	for c, s := range want {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != s {
			t.Errorf("json.Marshal(%v) = %s, want %s", c, b, s)
		}
	}
}

func TestInvariant_UnmarshalUnknownClassString(t *testing.T) {
	var c Class
	if err := json.Unmarshal([]byte(`"not-a-real-class"`), &c); err == nil {
		t.Error("expected an error unmarshaling an unrecognized class string")
	}
}

// TestInvariant_ConstructorsAgree verifies that StatementFromParts and
// ParseAttestationObject produce identical Verify results for the same
// underlying attestation, using the real captured YubiKey vector.
func TestInvariant_ConstructorsAgree(t *testing.T) {
	authData := readTestdata(t, "yubikey_es256_authdata.bin")
	attStmtBytes := readTestdata(t, "yubikey_es256_attstmt.cbor")
	cdh := readTestdata(t, "yubikey_es256_cdh.bin")

	stmt, err := decodePackedAttStmt(attStmtBytes)
	if err != nil {
		t.Fatalf("decoding fixture attStmt: %v", err)
	}

	stFromObject := Statement{
		Format:         "packed",
		AuthData:       authData,
		AttStmt:        attStmtBytes,
		ClientDataHash: cdh,
		RPID:           "localhost",
	}

	stFromParts, err := StatementFromParts("packed", authData, stmt.Alg, stmt.Sig, stmt.X5C, cdh, "localhost")
	if err != nil {
		t.Fatalf("StatementFromParts: %v", err)
	}

	at := Options{At: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	resObject, err := Verify(stFromObject, at)
	if err != nil {
		t.Fatalf("Verify(fromObject): %v", err)
	}
	resParts, err := Verify(stFromParts, at)
	if err != nil {
		t.Fatalf("Verify(fromParts): %v", err)
	}

	if !reflect.DeepEqual(resObject, resParts) {
		t.Errorf("results differ:\n  fromObject: %+v\n  fromParts:  %+v", resObject, resParts)
	}
	if !resObject.Verified {
		t.Fatalf("expected the real fixture to verify; reasons=%v", resObject.Reasons)
	}
}

func TestInvariant_ParseAttestationObjectRoundTrip(t *testing.T) {
	authData := readTestdata(t, "yubikey_eddsa_authdata.bin")
	attStmtBytes := readTestdata(t, "yubikey_eddsa_attstmt.cbor")
	cdh := readTestdata(t, "yubikey_eddsa_cdh.bin")

	attObj, err := marshalAttestationObjectForTest(t, "packed", authData, attStmtBytes)
	if err != nil {
		t.Fatalf("building attestation object: %v", err)
	}

	st, err := ParseAttestationObject(attObj, cdh, "localhost")
	if err != nil {
		t.Fatalf("ParseAttestationObject: %v", err)
	}

	res, err := Verify(st, Options{At: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Verified {
		t.Fatalf("expected verified, reasons=%v", res.Reasons)
	}
	if res.Class != ClassHardwareTouch {
		t.Errorf("expected touch, got %v", res.Class)
	}
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("reading testdata/%s: %v", name, err)
	}
	return b
}
