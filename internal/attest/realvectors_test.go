package attest

import (
	"testing"
	"time"
)

// TestVerify_RealVectors exercises Verify against real "packed" attestation
// captures from physical YubiKeys, licensed and sourced per
// testdata/PROVENANCE.txt (duo-labs/py_webauthn, BSD-3-Clause). They verify
// against this package's actual embedded, versioned trust material -- no
// synthetic CA is involved anywhere in this test.
//
// No equivalent real capture could be located for Google Titan or Feitian
// devices (see testdata/PROVENANCE.txt and the PR description); those two
// vendors' roots are still real and verified, but lack a positive test
// vector here.
func TestVerify_RealVectors(t *testing.T) {
	tests := []struct {
		name       string
		fixture    string
		rpID       string
		wantClass  Class
		wantAAGUID string
		wantVendor string
	}{
		{
			name:       "YubiKey, ES256, UV via PIN",
			fixture:    "yubikey_es256",
			rpID:       "localhost",
			wantClass:  ClassHardwarePIN,
			wantAAGUID: "6d44ba9b-f6ec-2e49-b930-0c8fe920cb73",
			wantVendor: "Yubico",
		},
		{
			name:       "YubiKey, Ed25519 credential key, no UV",
			fixture:    "yubikey_eddsa",
			rpID:       "localhost",
			wantClass:  ClassHardwareTouch,
			wantAAGUID: "c5ef55ff-ad9a-4b9f-b580-adebafe026d0",
			wantVendor: "Yubico",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := Statement{
				Format:         "packed",
				AuthData:       readTestdata(t, tc.fixture+"_authdata.bin"),
				AttStmt:        readTestdata(t, tc.fixture+"_attstmt.cbor"),
				ClientDataHash: readTestdata(t, tc.fixture+"_cdh.bin"),
				RPID:           tc.rpID,
			}

			res, err := Verify(st, Options{At: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !res.Verified {
				t.Fatalf("expected Verified=true, reasons=%v", res.Reasons)
			}
			if res.Class != tc.wantClass {
				t.Errorf("Class = %v, want %v", res.Class, tc.wantClass)
			}
			if res.AAGUID != tc.wantAAGUID {
				t.Errorf("AAGUID = %s, want %s", res.AAGUID, tc.wantAAGUID)
			}
			if res.Vendor != tc.wantVendor {
				t.Errorf("Vendor = %s, want %s", res.Vendor, tc.wantVendor)
			}
			if res.RootSetVersion != 1 {
				t.Errorf("RootSetVersion = %d, want 1", res.RootSetVersion)
			}
		})
	}
}

// TestVerify_RealVectorFailsBeforeItsValidityWindow confirms Options.At is
// actually load-bearing: the same real vector, checked at an instant before
// the leaf certificate's NotBefore, must not verify.
func TestVerify_RealVectorFailsBeforeItsValidityWindow(t *testing.T) {
	st := Statement{
		Format:         "packed",
		AuthData:       readTestdata(t, "yubikey_es256_authdata.bin"),
		AttStmt:        readTestdata(t, "yubikey_es256_attstmt.cbor"),
		ClientDataHash: readTestdata(t, "yubikey_es256_cdh.bin"),
		RPID:           "localhost",
	}

	res, err := Verify(st, Options{At: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Verified {
		t.Fatalf("expected Verified=false at an instant before the cert's validity window")
	}
	if res.Class != ClassUnknown {
		t.Errorf("Class = %v, want ClassUnknown", res.Class)
	}
}
