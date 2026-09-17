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
	Version       int                         `json:"version"`
	Roots         []rootManifestEntry         `json:"roots"`
	Intermediates []intermediateManifestEntry `json:"intermediates,omitempty"`
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

// intermediateManifestEntry describes a non-self-signed certificate that
// FIDO MDS3 lists in an authenticator's attestationRootCertificates
// alongside a bundled root (e.g. "Titan Security Key Signing", or Yubico's
// multi-level "Yubico Attestation Intermediate A/B 1" -> "Yubico FIDO
// Attestation A/B(2) 1" chain under "Yubico Attestation Root 1"). MDS lists
// these because some authenticators omit them from x5c; they are bundled
// here strictly as intermediates, added to VerifyOptions.Intermediates, and
// are never trust anchors.
//
// IssuerSHA256 is the DER SHA-256 of this certificate's immediate issuer,
// which may be a bundled root (a rootManifestEntry.SHA256) or another
// intermediate earlier in this same list (an intermediateManifestEntry.
// SHA256): manifest.Intermediates must be ordered parent-before-child so
// buildTrustStore can resolve each issuer from what it has already
// validated. buildTrustStore checks the signature on every hop
// (Certificate.CheckSignatureFrom the resolved issuer) and rejects the
// manifest if any link doesn't verify or an issuer can't be resolved.
type intermediateManifestEntry struct {
	File                string `json:"file"`
	Vendor              string `json:"vendor"`
	Subject             string `json:"subject"`
	SHA256              string `json:"sha256"`
	IssuerSHA256        string `json:"issuer_sha256"`
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
	intermediates  []*x509.Certificate
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

	// resolvable holds every certificate buildTrustStore has already
	// accepted as a valid issuer: the bundled roots to start, plus each
	// intermediate as it is itself validated. manifest.Intermediates must
	// list parents before children so this resolves.
	resolvable := make(map[string]*x509.Certificate, len(manifest.Roots)+len(manifest.Intermediates))
	resolvableVendor := make(map[string]string, len(manifest.Roots)+len(manifest.Intermediates))
	for _, entry := range manifest.Roots {
		pemBytes := rootPEMs[entry.File]
		block, _ := pem.Decode(pemBytes)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attest: %s: %w", entry.File, err)
		}
		resolvable[sha256Hex(cert.Raw)] = cert
		resolvableVendor[sha256Hex(cert.Raw)] = entry.Vendor
	}

	var intermediates []*x509.Certificate
	for _, entry := range manifest.Intermediates {
		pemBytes, ok := rootPEMs[entry.File]
		if !ok {
			return nil, fmt.Errorf("attest: manifest references intermediate %q but no such PEM was supplied", entry.File)
		}

		block, _ := pem.Decode(pemBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("attest: %s: not a PEM certificate", entry.File)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("attest: %s: %w", entry.File, err)
		}
		if isSelfSigned(cert) {
			return nil, fmt.Errorf("attest: %s: listed as an intermediate but is self-signed; it belongs in roots, not intermediates", entry.File)
		}

		gotSHA256 := sha256Hex(cert.Raw)
		wantSHA256 := strings.ToLower(entry.SHA256)
		if gotSHA256 != wantSHA256 {
			return nil, fmt.Errorf("attest: %s: sha256 %s does not match manifest %s", entry.File, gotSHA256, wantSHA256)
		}

		issuerSHA256 := strings.ToLower(entry.IssuerSHA256)
		if issuerSHA256 == "" {
			return nil, fmt.Errorf("attest: %s: intermediate manifest entry has no issuer_sha256", entry.File)
		}
		issuerCert, ok := resolvable[issuerSHA256]
		if !ok {
			return nil, fmt.Errorf("attest: %s: issuer_sha256 %s does not match any bundled root or earlier-listed intermediate (list parents before children)", entry.File, issuerSHA256)
		}
		if issuerVendor, ok := resolvableVendor[issuerSHA256]; !ok || issuerVendor != entry.Vendor {
			return nil, fmt.Errorf("attest: %s: vendor %q does not match issuer's vendor %q", entry.File, entry.Vendor, resolvableVendor[issuerSHA256])
		}

		// Verify this hop's signature against its resolved issuer. This
		// checks only the cryptographic link (and the issuer's CA/keyUsage
		// constraints), not time validity: opts.At governs expiry when a
		// real attestation is verified, and build time must not depend on
		// wall-clock time.
		if err := cert.CheckSignatureFrom(issuerCert); err != nil {
			return nil, fmt.Errorf("attest: %s: does not chain to issuer_sha256 %s: %w", entry.File, issuerSHA256, err)
		}

		resolvable[gotSHA256] = cert
		resolvableVendor[gotSHA256] = entry.Vendor
		intermediates = append(intermediates, cert)
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
		intermediates:  intermediates,
		rootSetVersion: manifest.Version,
		aaguids:        aaguids,
	}, nil
}

// addIntermediatesTo adds every bundled intermediate certificate to pool.
// These certificates are never trust anchors; they exist only so a chain
// that omits them from x5c (as MDS documents some authenticators do) can
// still be completed to a bundled root.
func (ts *trustStore) addIntermediatesTo(pool *x509.CertPool) {
	for _, cert := range ts.intermediates {
		pool.AddCert(cert)
	}
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

	rootPEMs := make(map[string][]byte, len(manifest.Roots)+len(manifest.Intermediates))
	for _, entry := range manifest.Roots {
		data, err := rootsFS.ReadFile("roots/" + entry.File)
		if err != nil {
			return nil, err
		}
		rootPEMs[entry.File] = data
	}
	for _, entry := range manifest.Intermediates {
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
