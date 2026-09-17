package attest

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestRootsManifestConsistency asserts, against the real embedded trust
// material (not a synthetic test store), that:
//   - every *.pem file in roots/ is listed in roots/manifest.json and vice
//     versa (a bijection between files on disk and manifest entries);
//   - every listed PEM parses as exactly one X.509 certificate;
//   - every listed certificate is a self-signed CA;
//   - every listed certificate's DER SHA-256 fingerprint matches the
//     manifest's recorded sha256.
func TestRootsManifestConsistency(t *testing.T) {
	manifestBytes, err := os.ReadFile("roots/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest rootManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decoding manifest: %v", err)
	}
	if manifest.Version < 1 {
		t.Errorf("manifest version is %d, want >= 1", manifest.Version)
	}

	entries, err := os.ReadDir("roots")
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pem") {
			onDisk = append(onDisk, e.Name())
		}
	}

	var inManifest []string
	byFile := map[string]rootManifestEntry{}
	for _, entry := range manifest.Roots {
		inManifest = append(inManifest, entry.File)
		byFile[entry.File] = entry
	}
	intermediateByFile := map[string]intermediateManifestEntry{}
	for _, entry := range manifest.Intermediates {
		inManifest = append(inManifest, entry.File)
		intermediateByFile[entry.File] = entry
	}

	sort.Strings(onDisk)
	sort.Strings(inManifest)
	if !equalStringSlices(onDisk, inManifest) {
		t.Fatalf("roots/*.pem on disk and manifest.json roots+intermediates disagree:\n  on disk:    %v\n  in manifest: %v", onDisk, inManifest)
	}

	rootsBySHA256 := map[string]*x509.Certificate{}

	for _, filename := range onDisk {
		t.Run(filename, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("roots", filename))
			if err != nil {
				t.Fatal(err)
			}

			block, rest := pem.Decode(data)
			if block == nil || block.Type != "CERTIFICATE" {
				t.Fatalf("%s: not a PEM certificate", filename)
			}
			if len(strings.TrimSpace(string(rest))) != 0 {
				t.Errorf("%s: unexpected trailing PEM data", filename)
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("%s: %v", filename, err)
			}

			if rootEntry, ok := byFile[filename]; ok {
				if !isSelfSigned(cert) {
					t.Errorf("%s: not a self-signed certificate", filename)
				}
				if !cert.IsCA || !cert.BasicConstraintsValid {
					t.Errorf("%s: not a valid CA certificate (IsCA=%v, BasicConstraintsValid=%v)", filename, cert.IsCA, cert.BasicConstraintsValid)
				}

				got := sha256Hex(cert.Raw)
				want := strings.ToLower(rootEntry.SHA256)
				if got != want {
					t.Errorf("%s: sha256 = %s, manifest says %s", filename, got, want)
				}
				rootsBySHA256[got] = cert

				if rootEntry.Vendor == "" {
					t.Errorf("%s: manifest entry has no vendor", filename)
				}
				if rootEntry.SourceURL == "" {
					t.Errorf("%s: manifest entry has no source_url", filename)
				}
				return
			}

			intEntry := intermediateByFile[filename]
			if isSelfSigned(cert) {
				t.Errorf("%s: listed as an intermediate but is self-signed", filename)
			}

			got := sha256Hex(cert.Raw)
			want := strings.ToLower(intEntry.SHA256)
			if got != want {
				t.Errorf("%s: sha256 = %s, manifest says %s", filename, got, want)
			}
			if intEntry.Vendor == "" {
				t.Errorf("%s: manifest entry has no vendor", filename)
			}
			if intEntry.SourceURL == "" {
				t.Errorf("%s: manifest entry has no source_url", filename)
			}
			if intEntry.IssuerSHA256 == "" {
				t.Errorf("%s: manifest entry has no issuer_sha256", filename)
			}
		})
	}

	// Every intermediate must actually chain to the root or earlier
	// intermediate it claims to, hop by hop: manifest.Intermediates must
	// list parents before children, mirroring buildTrustStore.
	resolved := map[string]*x509.Certificate{}
	for sha, cert := range rootsBySHA256 {
		resolved[sha] = cert
	}
	for _, entry := range manifest.Intermediates {
		t.Run(entry.File+"_chains_to_issuer", func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("roots", entry.File))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(data)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			issuer, ok := resolved[strings.ToLower(entry.IssuerSHA256)]
			if !ok {
				t.Fatalf("issuer_sha256 %s does not match any bundled root or earlier-listed intermediate", entry.IssuerSHA256)
			}
			if err := cert.CheckSignatureFrom(issuer); err != nil {
				t.Errorf("%s: does not chain to issuer: %v", entry.File, err)
			}
			resolved[sha256Hex(cert.Raw)] = cert
		})
	}
}

// TestEmbeddedTrustLoads asserts the package's actual embedded trust store
// (roots/*.pem, roots/manifest.json, metadata/aaguids.json) loads without
// error and is non-empty. embeddedTrust itself already panics at package
// init if this fails; this test exists so a broken trust store fails a
// specific, named test rather than every test in the package at once.
func TestEmbeddedTrustLoads(t *testing.T) {
	ts, err := loadEmbeddedTrust()
	if err != nil {
		t.Fatalf("loadEmbeddedTrust: %v", err)
	}
	if len(ts.rootVendor) == 0 {
		t.Error("no roots loaded")
	}
	if len(ts.aaguids) == 0 {
		t.Error("no aaguid metadata loaded")
	}
	if ts.rootSetVersion < 1 {
		t.Errorf("rootSetVersion = %d, want >= 1", ts.rootSetVersion)
	}

	// Cross-check: every vendor named in metadata/aaguids.json roots
	// actually resolves to a bundled root.
	for aaguid, rec := range ts.aaguids {
		found := false
		for sha := range rec.rootSHA256 {
			if _, ok := ts.rootVendor[sha]; ok {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("aaguid %x: none of its root_sha256 entries match a bundled root", aaguid)
		}
	}
}

// TestEmbeddedTrustCoversRealYubiKey5NFC asserts the embedded AAGUID table
// covers cb69481e-8ff7-4039-93ec-0a2729a154a8 ("YubiKey 5 Series"), the
// AAGUID of the most common real, currently-shipping hardware key stet will
// ever see, with a root that's actually bundled. Round-1 review found the
// table covered only 6 of ~95 real Yubico/Titan/Feitian FIDO2 AAGUIDs and
// this specific AAGUID was one of the missing ones; this test pins that gap
// closed.
func TestEmbeddedTrustCoversRealYubiKey5NFC(t *testing.T) {
	ts, err := loadEmbeddedTrust()
	if err != nil {
		t.Fatalf("loadEmbeddedTrust: %v", err)
	}
	id, err := parseAAGUIDString("cb69481e-8ff7-4039-93ec-0a2729a154a8")
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := ts.aaguids[id]
	if !ok {
		t.Fatal("cb69481e-8ff7-4039-93ec-0a2729a154a8 (YubiKey 5 Series) is not in the embedded AAGUID table")
	}
	if rec.vendor != "Yubico" {
		t.Errorf("vendor = %q, want Yubico", rec.vendor)
	}
	found := false
	for sha := range rec.rootSHA256 {
		if _, ok := ts.rootVendor[sha]; ok {
			found = true
			break
		}
	}
	if !found {
		t.Error("none of this AAGUID's root_sha256 entries match a bundled root")
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
