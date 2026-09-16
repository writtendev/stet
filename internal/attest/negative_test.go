package attest

import (
	"crypto/x509/pkix"
	"testing"
	"time"
)

// TestVerify_SyntheticNegatives is the table from STET-6's plan: every
// case starts from a scenario that would otherwise verify, changes exactly
// the thing its name describes, and expects ClassUnknown, Verified=false,
// and the exact reason code, with err == nil.
func TestVerify_SyntheticNegatives(t *testing.T) {
	tests := []struct {
		name   string
		modify func(sc scenario) scenario
		reason string
	}{
		{
			name:   "fmt none",
			modify: func(sc scenario) scenario { return sc }, // format is set separately below
			reason: reasonNoAttestation,
		},
		{
			name: "packed with no x5c is self-attestation even with a valid credential-key signature",
			modify: func(sc scenario) scenario {
				sc.x5cOverride = [][]byte{}
				return sc
			},
			reason: reasonSelfAttestation,
		},
		{
			name: "self-signed leaf",
			modify: func(sc scenario) scenario {
				sc.leaf.selfSigned = true
				return sc
			},
			reason: reasonSelfAttestation,
		},
		{
			name: "leaf equal to a trusted root",
			modify: func(sc scenario) scenario {
				sc.leafIsBundledRoot = true
				return sc
			},
			reason: reasonSelfAttestation,
		},
		{
			name: "leaf with IsCA=true",
			modify: func(sc scenario) scenario {
				sc.leaf.isCA = true
				return sc
			},
			reason: reasonLeafIsCA,
		},
		{
			name: "wrong OU",
			modify: func(sc scenario) scenario {
				sc.leaf.subject = pkixNameWithOU("Not Authenticator Attestation")
				return sc
			},
			reason: reasonLeafWrongOU,
		},
		{
			name: "leaf subject missing C/O/CN",
			modify: func(sc scenario) scenario {
				sc.leaf.subject = pkixNameOUOnly()
				return sc
			},
			reason: reasonLeafSubjectIncomplete,
		},
		{
			name: "signature over authData only",
			modify: func(sc scenario) scenario {
				sc.signOverAuthDataOnly = true
				return sc
			},
			reason: reasonBadSignature,
		},
		{
			name: "signature over clientDataHash only",
			modify: func(sc scenario) scenario {
				sc.signOverCDHOnly = true
				return sc
			},
			reason: reasonBadSignature,
		},
		{
			name: "flipped signature byte",
			modify: func(sc scenario) scenario {
				sc.tamperSigByte = true
				return sc
			},
			reason: reasonBadSignature,
		},
		{
			name: "flipped authData byte after signing",
			modify: func(sc scenario) scenario {
				// Index 55 is the first byte of the credential id, well
				// outside the rpIdHash/flags/signCount/aaguid region, so
				// this is attributable to the signature check alone.
				sc.tamperAuthDataByteAfterSign = 55
				return sc
			},
			reason: reasonBadSignature,
		},
		{
			name: "wrong clientDataHash",
			modify: func(sc scenario) scenario {
				sc.cdhOverrideForTransmit = mustFixedCDH(1)
				return sc
			},
			reason: reasonBadSignature,
		},
		{
			name: "alg/key mismatch: ES256 alg with a P-384 key",
			modify: func(sc scenario) scenario {
				sc.leaf.keyKind = keyP384
				return sc
			},
			reason: reasonAlgKeyMismatch,
		},
		{
			name: "unsupported alg",
			modify: func(sc scenario) scenario {
				sc.alg = -99999
				sc.rawSigOverride = []byte{0x00}
				return sc
			},
			reason: reasonUnsupportedAlg,
		},
		{
			name: "AAGUID extension absent",
			modify: func(sc scenario) scenario {
				sc.leaf.aaguidExt = &aaguidExtSpec{absent: true}
				return sc
			},
			reason: reasonAAGUIDUnbound,
		},
		{
			name: "AAGUID extension critical",
			modify: func(sc scenario) scenario {
				sc.leaf.aaguidExt = &aaguidExtSpec{critical: true}
				return sc
			},
			reason: reasonAAGUIDExtCritical,
		},
		{
			name: "AAGUID extension 15 bytes",
			modify: func(sc scenario) scenario {
				sc.leaf.aaguidExt = &aaguidExtSpec{rawOctets: 15}
				return sc
			},
			reason: reasonAAGUIDExtMalformed,
		},
		{
			name: "AAGUID extension 17 bytes",
			modify: func(sc scenario) scenario {
				sc.leaf.aaguidExt = &aaguidExtSpec{rawOctets: 17}
				return sc
			},
			reason: reasonAAGUIDExtMalformed,
		},
		{
			name: "AAGUID extension trailing data",
			modify: func(sc scenario) scenario {
				sc.leaf.aaguidExt = &aaguidExtSpec{trailing: true}
				return sc
			},
			reason: reasonAAGUIDExtMalformed,
		},
		{
			name: "AAGUID extension mismatched",
			modify: func(sc scenario) scenario {
				other := testAAGUID()
				other[0] ^= 0xFF
				sc.leaf.aaguidExt = &aaguidExtSpec{content: other[:]}
				return sc
			},
			reason: reasonAAGUIDMismatch,
		},
		{
			name: "AAGUID all-zero",
			modify: func(sc scenario) scenario {
				var zero [16]byte
				sc.aaguid = zero
				sc.leaf.aaguid = zero
				sc.leaf.aaguidExt = &aaguidExtSpec{content: zero[:]}
				sc.omitFromMetadata = false
				return sc
			},
			reason: reasonAAGUIDZero,
		},
		{
			name: "chain to an untrusted CA",
			modify: func(sc scenario) scenario {
				sc.untrustedChain = true
				return sc
			},
			reason: reasonChainUntrusted,
		},
		{
			name: "root supplied inside x5c but not in the trust store",
			modify: func(sc scenario) scenario {
				sc.untrustedChain = true
				sc.includeSigningRootInX5C = true
				return sc
			},
			reason: reasonChainUntrusted,
		},
		{
			name: "At after notAfter",
			modify: func(sc scenario) scenario {
				sc.verifyAt = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
				return sc
			},
			reason: reasonChainExpired,
		},
		{
			name: "AAGUID not in table",
			modify: func(sc scenario) scenario {
				sc.omitFromMetadata = true
				return sc
			},
			reason: reasonAAGUIDNotInMetadata,
		},
		{
			name: "AAGUID whose table vendor differs from the anchoring root",
			modify: func(sc scenario) scenario {
				sc.metadataRootSHA256Override = sha256Hex([]byte("not the real root"))
				return sc
			},
			reason: reasonAAGUIDVendorMismatch,
		},
		{
			name: "UP flag clear",
			modify: func(sc scenario) scenario {
				sc.up = false
				return sc
			},
			reason: reasonUserNotPresent,
		},
		{
			name: "rpIdHash mismatch",
			modify: func(sc scenario) scenario {
				sc.verifyRPIDOverride = "attacker.example"
				return sc
			},
			reason: reasonRPIDMismatch,
		},
		{
			name: "ecdaaKeyId present",
			modify: func(sc scenario) scenario {
				sc.ecdaaKeyID = []byte{0x01, 0x02, 0x03, 0x04}
				return sc
			},
			reason: reasonUnsupportedECDAA,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc := baseScenario()
			sc = tc.modify(sc)

			var res Result
			var err error
			if tc.name == "fmt none" {
				st, trust := sc.build(t)
				st.Format = "none"
				res, err = verify(st, Options{At: sc.verifyAt}, trust)
			} else {
				res, err = sc.verify(t)
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Verified {
				t.Fatalf("expected Verified=false, got true")
			}
			if res.Class != ClassUnknown {
				t.Errorf("expected ClassUnknown, got %v", res.Class)
			}
			if len(res.Reasons) != 1 || res.Reasons[0] != tc.reason {
				t.Errorf("expected reasons=[%s], got %v", tc.reason, res.Reasons)
			}
		})
	}
}

// TestVerify_UnsupportedFormats covers every non-packed, non-none format
// string: each classifies as unknown with reasonUnsupportedFormat.
func TestVerify_UnsupportedFormats(t *testing.T) {
	for _, format := range []string{"fido-u2f", "tpm", "android-key", "android-safetynet", "apple", "bogus"} {
		t.Run(format, func(t *testing.T) {
			sc := baseScenario()
			st, trust := sc.build(t)
			st.Format = format

			res, err := verify(st, Options{At: sc.verifyAt}, trust)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Verified || res.Class != ClassUnknown {
				t.Fatalf("expected unverified/unknown, got %+v", res)
			}
			if len(res.Reasons) != 1 || res.Reasons[0] != reasonUnsupportedFormat {
				t.Errorf("expected reasons=[%s], got %v", reasonUnsupportedFormat, res.Reasons)
			}
		})
	}
}

func pkixNameWithOU(ou string) pkix.Name {
	n := defaultLeafSubject()
	n.OrganizationalUnit = []string{ou}
	return n
}

func pkixNameOUOnly() pkix.Name {
	return pkix.Name{OrganizationalUnit: []string{requiredLeafOU}}
}
