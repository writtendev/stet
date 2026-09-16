package attest

import "testing"

// TestVerify_AllAlgorithms exercises every attestation signature algorithm
// Verify accepts (algorithm step 6) on an otherwise-valid synthetic
// attestation, so each algorithm's success path is covered, not just its
// mismatch/rejection paths.
func TestVerify_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name string
		alg  int64
		kind keyKind
	}{
		{"ES256", algES256, keyP256},
		{"ES384", algES384, keyP384},
		{"EdDSA", algEdDSA, keyEd25519},
		{"RS256", algRS256, keyRSA2048},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc := baseScenario()
			sc.alg = tc.alg
			sc.leaf.keyKind = tc.kind

			res, err := sc.verify(t)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !res.Verified {
				t.Fatalf("expected Verified=true, reasons=%v", res.Reasons)
			}
		})
	}
}
