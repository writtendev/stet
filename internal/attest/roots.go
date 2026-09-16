package attest

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

//go:embed roots/*.pem roots/manifest.json
var rootsFS embed.FS

//go:embed metadata/aaguids.json
var aaguidsJSON []byte

// rootManifest is the schema of roots/manifest.json.
type rootManifest struct {
	Version int                 `json:"version"`
	Roots   []rootManifestEntry `json:"roots"`
}

type rootManifestEntry struct {
	File                string `json:"file"`
	Vendor              string `json:"vendor"`
	Subject             string `json:"subject"`
	SHA256              string `json:"sha256"`
	NotAfter            string `json:"not_after"`
	SourceURL           string `json:"source_url"`
	Retrieved           string `json:"retrieved"`
	CrossCheckedAgainst string `json:"cross_checked_against"`
}

// aaguidMetadata is the schema of metadata/aaguids.json.
type aaguidMetadata struct {
	Version int             `json:"version"`
	Source  json.RawMessage `json:"source"`
	Entries []aaguidEntry   `json:"entries"`
}

type aaguidEntry struct {
	AAGUID      string   `json:"aaguid"`
	Vendor      string   `json:"vendor"`
	Description string   `json:"description"`
	RootSHA256  []string `json:"root_sha256"`
	UVMethods   []string `json:"uv_methods"`
}

// trustStore is the trust material Verify checks a statement against: a
// pool of vendor root CAs and the AAGUID capability table cross-checked
// against them. Production code always uses embeddedTrust; tests build
// their own with buildTrustStore so they can inject a throwaway CA without
// ever touching the embedded, versioned root set.
type trustStore struct {
	pool           *x509.CertPool
	rootVendor     map[string]string // sha256 hex (of cert.Raw) -> vendor
	rootSetVersion int
	aaguids        map[[16]byte]aaguidRecord
}

type aaguidRecord struct {
	vendor     string
	model      string
	rootSHA256 map[string]bool
	uvMethods  map[string]bool
}

// buildTrustStore assembles a trustStore from a manifest, the raw AAGUID
// metadata JSON, and a lookup of manifest filename -> PEM bytes. Every
// manifest entry must have a corresponding PEM whose DER-encoded SHA-256
// fingerprint matches the manifest, and must be a self-signed CA
// certificate; buildTrustStore returns an error otherwise.
func buildTrustStore(rootPEMs map[string][]byte, manifest rootManifest, aaguidRaw []byte) (*trustStore, error) {
	pool := x509.NewCertPool()
	rootVendor := make(map[string]string, len(manifest.Roots))

	for _, entry := range manifest.Roots {
		pemBytes, ok := rootPEMs[entry.File]
		if !ok {
			return nil, fmt.Errorf("attest: manifest references %q but no such root PEM was supplied", entry.File)
		}

		block, _ := pem.Decode(pemBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("attest: %s: not a PEM certificate", entry.File)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attest: %s: %w", entry.File, err)
		}
		if !isSelfSigned(cert) {
			return nil, fmt.Errorf("attest: %s: not a self-signed CA certificate", entry.File)
		}

		gotSHA256 := sha256Hex(cert.Raw)
		wantSHA256 := strings.ToLower(entry.SHA256)
		if gotSHA256 != wantSHA256 {
			return nil, fmt.Errorf("attest: %s: sha256 %s does not match manifest %s", entry.File, gotSHA256, wantSHA256)
		}

		pool.AddCert(cert)
		rootVendor[gotSHA256] = entry.Vendor
	}

	var meta aaguidMetadata
	if err := json.Unmarshal(aaguidRaw, &meta); err != nil {
		return nil, fmt.Errorf("attest: decoding aaguid metadata: %w", err)
	}

	aaguids := make(map[[16]byte]aaguidRecord, len(meta.Entries))
	for _, e := range meta.Entries {
		id, err := parseAAGUIDString(e.AAGUID)
		if err != nil {
			return nil, fmt.Errorf("attest: aaguid metadata: %w", err)
		}

		rec := aaguidRecord{
			vendor:     e.Vendor,
			model:      e.Description,
			rootSHA256: make(map[string]bool, len(e.RootSHA256)),
			uvMethods:  make(map[string]bool, len(e.UVMethods)),
		}
		for _, s := range e.RootSHA256 {
			rec.rootSHA256[strings.ToLower(s)] = true
		}
		for _, m := range e.UVMethods {
			rec.uvMethods[m] = true
		}
		aaguids[id] = rec
	}

	return &trustStore{
		pool:           pool,
		rootVendor:     rootVendor,
		rootSetVersion: manifest.Version,
		aaguids:        aaguids,
	}, nil
}

// isBundledRoot reports whether cert's DER encoding is byte-equal to one of
// the trust store's own bundled roots.
func (ts *trustStore) isBundledRoot(cert *x509.Certificate) bool {
	_, ok := ts.rootVendor[sha256Hex(cert.Raw)]
	return ok
}

// lookupRoot returns the vendor and sha256 hex fingerprint recorded for
// cert, if cert is one of the trust store's bundled roots.
func (ts *trustStore) lookupRoot(cert *x509.Certificate) (sha256hex, vendor string, ok bool) {
	sha256hex = sha256Hex(cert.Raw)
	vendor, ok = ts.rootVendor[sha256hex]
	return sha256hex, vendor, ok
}

func sha256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// parseAAGUIDString parses a canonical (optionally dashed) 32-hex-digit
// AAGUID, as it appears in metadata/aaguids.json, into 16 bytes.
func parseAAGUIDString(s string) ([16]byte, error) {
	hexOnly := strings.ReplaceAll(s, "-", "")
	if len(hexOnly) != 32 {
		return [16]byte{}, fmt.Errorf("aaguid %q is not 32 hex digits", s)
	}
	b, err := hex.DecodeString(hexOnly)
	if err != nil {
		return [16]byte{}, fmt.Errorf("aaguid %q: %w", s, err)
	}
	var out [16]byte
	copy(out[:], b)
	return out, nil
}

// loadEmbeddedTrust builds the trust store from the files this package
// embeds: roots/*.pem, roots/manifest.json, and metadata/aaguids.json.
// Nothing is ever fetched over the network; see roots/manifest.json and
// metadata/aaguids.json for how and when this material was retrieved and
// verified.
func loadEmbeddedTrust() (*trustStore, error) {
	manifestBytes, err := rootsFS.ReadFile("roots/manifest.json")
	if err != nil {
		return nil, err
	}
	var manifest rootManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("attest: decoding roots/manifest.json: %w", err)
	}

	rootPEMs := make(map[string][]byte, len(manifest.Roots))
	for _, entry := range manifest.Roots {
		data, err := rootsFS.ReadFile("roots/" + entry.File)
		if err != nil {
			return nil, err
		}
		rootPEMs[entry.File] = data
	}

	return buildTrustStore(rootPEMs, manifest, aaguidsJSON)
}

// embeddedTrust is the trust store every exported Verify call uses. It is
// built once, from the package's embedded files; a failure to load it is a
// build-time invariant violation, so it panics rather than silently running
// with no trust material at all.
var embeddedTrust = func() *trustStore {
	ts, err := loadEmbeddedTrust()
	if err != nil {
		panic("attest: embedded trust material is invalid: " + err.Error())
	}
	return ts
}()
