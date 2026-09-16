package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// buildTestIntermediate creates a non-self-signed CA certificate signed by
// root, wrapped as a *testCA so buildLeaf can sign a leaf under it exactly
// as it would under a top-level root.
func buildTestIntermediate(t *testing.T, root *testCA) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating intermediate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "stet synthetic test intermediate (never trusted in production)"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, &key.PublicKey, root.key)
	if err != nil {
		t.Fatalf("creating intermediate cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing intermediate cert: %v", err)
	}
	return &testCA{cert: cert, key: key, der: der}
}

// buildChainTrustStore builds a trustStore whose only root is root, bundling
// inter (if non-nil) as a manifest.Intermediates entry the way
// roots/manifest.json bundles MDS-documented intermediates -- never a trust
// anchor, only material buildTrustStore hop-verifies and verifyChain adds to
// VerifyOptions.Intermediates via addIntermediatesTo.
func buildChainTrustStore(t *testing.T, root *testCA, inter *testCA) *trustStore {
	t.Helper()

	rootPEMs := map[string][]byte{
		"root.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.der}),
	}
	manifest := rootManifest{
		Version: 999,
		Roots: []rootManifestEntry{{
			File:   "root.pem",
			Vendor: "TestVendor",
			SHA256: sha256Hex(root.der),
		}},
	}
	if inter != nil {
		rootPEMs["inter.pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.der})
		manifest.Intermediates = []intermediateManifestEntry{{
			File:         "inter.pem",
			Vendor:       "TestVendor",
			SHA256:       sha256Hex(inter.der),
			IssuerSHA256: sha256Hex(root.der),
		}}
	}

	ts, err := buildTrustStore(rootPEMs, manifest, aaguidJSONFor())
	if err != nil {
		t.Fatalf("building test trust store: %v", err)
	}
	return ts
}

// TestVerifyChain_BundledIntermediate is the regression test round-2 review
// asked for: verifyChain's bundled-intermediate path (trust.addIntermediatesTo,
// the round-1 medium fix) had no test that actually exercised it. A leaf
// whose x5c omits its issuing intermediate -- exactly what MDS documents some
// real authenticators (Titan v2, YubiKey 5.7+) doing -- must still verify
// when that intermediate is bundled in the trust store, and must fail to
// verify when it is not.
func TestVerifyChain_BundledIntermediate(t *testing.T) {
	root := newTestCA(t)
	inter := buildTestIntermediate(t, root)
	leafDER, _ := buildLeaf(t, inter, leafSpec{keyKind: keyP256, subject: defaultLeafSubject()})
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}

	// x5c carries only the leaf: the intermediate is omitted, exactly as
	// MDS documents some real authenticators doing.
	x5c := [][]byte{leafDER}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("bundled intermediate completes the chain", func(t *testing.T) {
		trust := buildChainTrustStore(t, root, inter)
		chains, reason := verifyChain(leaf, x5c, trust, at)
		if reason != "" {
			t.Fatalf("reason = %q, want \"\" (chain should verify via the bundled intermediate)", reason)
		}
		if len(chains) == 0 {
			t.Fatal("no chains returned")
		}
		// leaf -> intermediate -> root: the completed chain must actually
		// pass through the bundled intermediate, not some other path.
		found := false
		for _, chain := range chains {
			for _, c := range chain {
				if sha256Hex(c.Raw) == sha256Hex(inter.der) {
					found = true
				}
			}
		}
		if !found {
			t.Error("no returned chain passes through the bundled intermediate")
		}
	})

	t.Run("without the bundled intermediate the chain fails", func(t *testing.T) {
		// Same leaf and x5c (still omitting the intermediate), but this
		// trust store's manifest never lists it: this is the behavior a
		// regression that dropped trust.addIntermediatesTo from
		// verifyChain would produce even with an intermediate-carrying
		// manifest, since the pool it feeds would never be populated.
		trust := buildChainTrustStore(t, root, nil)
		chains, reason := verifyChain(leaf, x5c, trust, at)
		if reason != reasonChainUntrusted {
			t.Fatalf("reason = %q, want %q", reason, reasonChainUntrusted)
		}
		if len(chains) != 0 {
			t.Errorf("expected no chains, got %d", len(chains))
		}
	})
}
