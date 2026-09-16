package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// statusReports filtering (round-2 [medium]: a revoked or compromised AAGUID
// would otherwise be bundled as trusted).
// ---------------------------------------------------------------------------

func TestCompromisedStatusIn(t *testing.T) {
	cases := []struct {
		name    string
		reports []mdsStatusReport
		want    string
	}{
		{"no reports", nil, ""},
		{"clean history", []mdsStatusReport{{Status: "FIDO_CERTIFIED"}, {Status: "UPDATE_AVAILABLE"}}, ""},
		{"revoked", []mdsStatusReport{{Status: "REVOKED"}}, "REVOKED"},
		{"attestation key compromise", []mdsStatusReport{{Status: "ATTESTATION_KEY_COMPROMISE"}}, "ATTESTATION_KEY_COMPROMISE"},
		{"user verification bypass", []mdsStatusReport{{Status: "USER_VERIFICATION_BYPASS"}}, "USER_VERIFICATION_BYPASS"},
		{"user key remote compromise", []mdsStatusReport{{Status: "USER_KEY_REMOTE_COMPROMISE"}}, "USER_KEY_REMOTE_COMPROMISE"},
		{"user key physical compromise", []mdsStatusReport{{Status: "USER_KEY_PHYSICAL_COMPROMISE"}}, "USER_KEY_PHYSICAL_COMPROMISE"},
		{
			"a later clean report does not retract an earlier compromise",
			[]mdsStatusReport{{Status: "ATTESTATION_KEY_COMPROMISE"}, {Status: "FIDO_CERTIFIED"}},
			"ATTESTATION_KEY_COMPROMISE",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := compromisedStatusIn(tc.reports); got != tc.want {
				t.Errorf("compromisedStatusIn(%+v) = %q, want %q", tc.reports, got, tc.want)
			}
		})
	}
}

// syntheticSelfSignedRoot creates a self-signed CA certificate whose Subject
// CommonName is cn, so vendorFromRootSubject can identify it as a covered
// vendor's root the way it identifies the real bundled roots: by Subject,
// not by any product-name string.
func syntheticSelfSignedRoot(t *testing.T, cn string, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating synthetic root: %v", err)
	}
	return der
}

// TestExtractVendorEntries_ExcludesCompromisedStatus is the fixture-driven
// unit test round-2 review asked for: a covered-vendor FIDO2 entry whose
// statusReports carries a compromise/revocation status must never appear in
// the extracted AAGUID table, and must be recorded in extraction.excluded
// instead of silently vanishing.
func TestExtractVendorEntries_ExcludesCompromisedStatus(t *testing.T) {
	rootDER := syntheticSelfSignedRoot(t, "Yubico Test Root", 1)
	rootB64 := base64.StdEncoding.EncodeToString(rootDER)

	mkEntry := func(aaguid, description string, reports []mdsStatusReport) mdsEntry {
		return mdsEntry{
			AAGUID: aaguid,
			MetadataStatement: &mdsMetadataStmt{
				Description:                 description,
				ProtocolFamily:              "fido2",
				AttestationRootCertificates: []string{rootB64},
			},
			StatusReports: reports,
		}
	}

	payload := &mdsPayload{
		No: 1,
		Entries: []mdsEntry{
			mkEntry("11111111-1111-1111-1111-111111111111", "Good Key",
				[]mdsStatusReport{{Status: "FIDO_CERTIFIED"}}),
			mkEntry("22222222-2222-2222-2222-222222222222", "Compromised Key",
				[]mdsStatusReport{{Status: "FIDO_CERTIFIED"}, {Status: "ATTESTATION_KEY_COMPROMISE"}}),
			mkEntry("33333333-3333-3333-3333-333333333333", "Revoked Key",
				[]mdsStatusReport{{Status: "REVOKED"}}),
			mkEntry("44444444-4444-4444-4444-444444444444", "Bypass Key",
				[]mdsStatusReport{{Status: "USER_VERIFICATION_BYPASS"}}),
		},
	}

	ex := extractVendorEntries(payload)

	gotAAGUIDs := map[string]bool{}
	for _, a := range ex.aaguids {
		gotAAGUIDs[a.AAGUID] = true
	}
	if !gotAAGUIDs["11111111-1111-1111-1111-111111111111"] {
		t.Error("a clean entry was excluded")
	}
	for _, bad := range []string{
		"22222222-2222-2222-2222-222222222222",
		"33333333-3333-3333-3333-333333333333",
		"44444444-4444-4444-4444-444444444444",
	} {
		if gotAAGUIDs[bad] {
			t.Errorf("compromised/revoked entry %s was NOT excluded", bad)
		}
	}
	if len(ex.aaguids) != 1 {
		t.Errorf("aaguids = %d entries, want 1 (only the clean one)", len(ex.aaguids))
	}
	if len(ex.excluded) != 3 {
		t.Fatalf("excluded = %d entries, want 3", len(ex.excluded))
	}
	statusByAAGUID := map[string]string{}
	for _, e := range ex.excluded {
		statusByAAGUID[e.AAGUID] = e.Status
		if e.Vendor != "Yubico" {
			t.Errorf("excluded entry %s: vendor = %q, want Yubico", e.AAGUID, e.Vendor)
		}
	}
	want := map[string]string{
		"22222222-2222-2222-2222-222222222222": "ATTESTATION_KEY_COMPROMISE",
		"33333333-3333-3333-3333-333333333333": "REVOKED",
		"44444444-4444-4444-4444-444444444444": "USER_VERIFICATION_BYPASS",
	}
	for aaguid, wantStatus := range want {
		if statusByAAGUID[aaguid] != wantStatus {
			t.Errorf("excluded[%s].Status = %q, want %q", aaguid, statusByAAGUID[aaguid], wantStatus)
		}
	}
}

// ---------------------------------------------------------------------------
// MDS3 blob JWT verification: leaf must be the actual FIDO MDS signer, not
// merely any certificate that chains to GlobalSign Root R3 (round-2
// [medium]).
// ---------------------------------------------------------------------------

// buildTestChain creates a self-signed test root and a leaf signed by it,
// with the leaf's SAN set to dnsName, valid over [notBefore, notAfter].
func buildTestChain(t *testing.T, dnsName string, notBefore, notAfter time.Time) (rootCert *x509.Certificate, leafCert *x509.Certificate) {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "stet synthetic test MDS root (never trusted in production)"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return rootCert, leafCert
}

func TestVerifyLeafChain(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("correct DNS name and validity window verifies", func(t *testing.T) {
		root, leaf := buildTestChain(t, "mds.fidoalliance.org",
			time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
		roots := x509.NewCertPool()
		roots.AddCert(root)
		if err := verifyLeafChain([]*x509.Certificate{leaf}, roots, "mds.fidoalliance.org", at); err != nil {
			t.Errorf("verifyLeafChain: %v", err)
		}
	})

	t.Run("leaf for a different DNS name is rejected", func(t *testing.T) {
		// Exactly the failure scenario round-2 review raised: an
		// otherwise-valid, otherwise-trusted-root-chaining certificate
		// issued to someone other than the FIDO MDS signer.
		root, leaf := buildTestChain(t, "unrelated.example.com",
			time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
		roots := x509.NewCertPool()
		roots.AddCert(root)
		if err := verifyLeafChain([]*x509.Certificate{leaf}, roots, "mds.fidoalliance.org", at); err == nil {
			t.Error("expected an error for a leaf issued to a different DNS name, got none")
		}
	})

	t.Run("expired leaf is rejected", func(t *testing.T) {
		root, leaf := buildTestChain(t, "mds.fidoalliance.org",
			time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC))
		roots := x509.NewCertPool()
		roots.AddCert(root)
		if err := verifyLeafChain([]*x509.Certificate{leaf}, roots, "mds.fidoalliance.org", at); err == nil {
			t.Error("expected an error for a leaf outside its validity window, got none")
		}
	})

	t.Run("leaf not chaining to the given root is rejected", func(t *testing.T) {
		_, leaf := buildTestChain(t, "mds.fidoalliance.org",
			time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
		otherRoot, _ := buildTestChain(t, "mds.fidoalliance.org",
			time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
		roots := x509.NewCertPool()
		roots.AddCert(otherRoot)
		if err := verifyLeafChain([]*x509.Certificate{leaf}, roots, "mds.fidoalliance.org", at); err == nil {
			t.Error("expected an error for a leaf signed by an untrusted root, got none")
		}
	})
}

// ---------------------------------------------------------------------------
// Root-set version bump (round-2 [minor]: regenerating never bumped it, so
// Result.RootSetVersion couldn't tell trust sets apart across a run).
// ---------------------------------------------------------------------------

func readManifestAndAAGUIDs(t *testing.T, attestDir string) (rootManifest, aaguidMetadata) {
	t.Helper()
	var m rootManifest
	mb, err := os.ReadFile(filepath.Join(attestDir, "roots", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatal(err)
	}
	var a aaguidMetadata
	ab, err := os.ReadFile(filepath.Join(attestDir, "metadata", "aaguids.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ab, &a); err != nil {
		t.Fatal(err)
	}
	return m, a
}

func TestWriteOutputs_VersionBump(t *testing.T) {
	rootDER := syntheticSelfSignedRoot(t, "Yubico Test Root", 1)
	entry := aaguidOut{AAGUID: "11111111-1111-1111-1111-111111111111", Vendor: "Yubico", Description: "Key A", RootSHA256: []string{sha256Hex(rootDER)}}

	newExtraction := func() *extraction {
		return &extraction{
			aaguids: []aaguidOut{entry},
			roots: map[string]*certOut{
				sha256Hex(rootDER): {
					cert: mustParseCert(t, rootDER), sha256: sha256Hex(rootDER), vendor: "Yubico",
					selfSigned: true, firstAAGUID: entry.AAGUID, firstDescription: entry.Description,
				},
			},
			intermediates: map[string]*certOut{},
		}
	}
	payload := &mdsPayload{No: 1}

	t.Run("first write requires an explicit version", func(t *testing.T) {
		dir := t.TempDir()
		if err := writeOutputs(dir, payload, newExtraction(), 0); err == nil {
			t.Fatal("expected an error when the root set changes with -version=0, got none")
		}
	})

	t.Run("first write with an explicit version succeeds and is recorded", func(t *testing.T) {
		dir := t.TempDir()
		if err := writeOutputs(dir, payload, newExtraction(), 1); err != nil {
			t.Fatalf("writeOutputs: %v", err)
		}
		m, a := readManifestAndAAGUIDs(t, dir)
		if m.Version != 1 {
			t.Errorf("manifest version = %d, want 1", m.Version)
		}
		if a.Version != 1 {
			t.Errorf("aaguids version = %d, want 1", a.Version)
		}
	})

	t.Run("re-running with no changes keeps the version and ignores -version", func(t *testing.T) {
		dir := t.TempDir()
		if err := writeOutputs(dir, payload, newExtraction(), 1); err != nil {
			t.Fatalf("writeOutputs (initial): %v", err)
		}
		// Same extraction again: nothing changed, so even though -version=99
		// is passed, the version already on disk must be kept.
		if err := writeOutputs(dir, payload, newExtraction(), 99); err != nil {
			t.Fatalf("writeOutputs (no-op re-run): %v", err)
		}
		m, a := readManifestAndAAGUIDs(t, dir)
		if m.Version != 1 {
			t.Errorf("manifest version = %d, want 1 (unchanged)", m.Version)
		}
		if a.Version != 1 {
			t.Errorf("aaguids version = %d, want 1 (unchanged)", a.Version)
		}
	})

	t.Run("a changed aaguid set without -version is refused", func(t *testing.T) {
		dir := t.TempDir()
		if err := writeOutputs(dir, payload, newExtraction(), 1); err != nil {
			t.Fatalf("writeOutputs (initial): %v", err)
		}
		changed := newExtraction()
		changed.aaguids[0].Description = "Key A (renamed)"
		if err := writeOutputs(dir, payload, changed, 0); err == nil {
			t.Fatal("expected an error: aaguid entries changed but -version was not given")
		}
		if err := writeOutputs(dir, payload, changed, 1); err == nil {
			t.Fatal("expected an error: -version=1 does not exceed the version already on disk")
		}
		// Confirm the refused writes didn't corrupt what's on disk.
		m, a := readManifestAndAAGUIDs(t, dir)
		if m.Version != 1 || a.Version != 1 || a.Entries[0].Description != "Key A" {
			t.Errorf("a refused write mutated committed state: manifest=%d aaguids=%d description=%q", m.Version, a.Version, a.Entries[0].Description)
		}
	})

	t.Run("a changed aaguid set with a higher -version succeeds", func(t *testing.T) {
		dir := t.TempDir()
		if err := writeOutputs(dir, payload, newExtraction(), 1); err != nil {
			t.Fatalf("writeOutputs (initial): %v", err)
		}
		changed := newExtraction()
		changed.aaguids[0].Description = "Key A (renamed)"
		if err := writeOutputs(dir, payload, changed, 2); err != nil {
			t.Fatalf("writeOutputs (bumped): %v", err)
		}
		m, a := readManifestAndAAGUIDs(t, dir)
		if m.Version != 2 || a.Version != 2 {
			t.Errorf("manifest version = %d, aaguids version = %d, want 2 and 2", m.Version, a.Version)
		}
		if a.Entries[0].Description != "Key A (renamed)" {
			t.Errorf("aaguid entry not updated: %q", a.Entries[0].Description)
		}
	})

	t.Run("a new root without -version is refused", func(t *testing.T) {
		dir := t.TempDir()
		if err := writeOutputs(dir, payload, newExtraction(), 1); err != nil {
			t.Fatalf("writeOutputs (initial): %v", err)
		}
		withNewRoot := newExtraction()
		newRootDER := syntheticSelfSignedRoot(t, "Feitian Test Root", 2)
		withNewRoot.roots[sha256Hex(newRootDER)] = &certOut{
			cert: mustParseCert(t, newRootDER), sha256: sha256Hex(newRootDER), vendor: "Feitian",
			selfSigned: true, firstAAGUID: entry.AAGUID, firstDescription: entry.Description,
		}
		if err := writeOutputs(dir, payload, withNewRoot, 0); err == nil {
			t.Fatal("expected an error: a new root was added but -version was not given")
		}
	})
}

func mustParseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
