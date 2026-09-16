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

	sort.Strings(onDisk)
	sort.Strings(inManifest)
	if !equalStringSlices(onDisk, inManifest) {
		t.Fatalf("roots/*.pem on disk and manifest.json roots disagree:\n  on disk:    %v\n  in manifest: %v", onDisk, inManifest)
	}

	for _, filename := range onDisk {
		t.Run(filename, func(t *testing.T) {
			entry := byFile[filename]
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

			if !isSelfSigned(cert) {
				t.Errorf("%s: not a self-signed certificate", filename)
			}
			if !cert.IsCA || !cert.BasicConstraintsValid {
				t.Errorf("%s: not a valid CA certificate (IsCA=%v, BasicConstraintsValid=%v)", filename, cert.IsCA, cert.BasicConstraintsValid)
			}

			got := sha256Hex(cert.Raw)
			want := strings.ToLower(entry.SHA256)
			if got != want {
				t.Errorf("%s: sha256 = %s, manifest says %s", filename, got, want)
			}

			if entry.Vendor == "" {
				t.Errorf("%s: manifest entry has no vendor", filename)
			}
			if entry.SourceURL == "" {
				t.Errorf("%s: manifest entry has no source_url", filename)
			}
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
