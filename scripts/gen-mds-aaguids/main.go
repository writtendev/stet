// Command gen-mds-aaguids regenerates internal/attest/metadata/aaguids.json
// and internal/attest/roots/manifest.json (plus any new roots/*.pem it
// bundles) from the FIDO Alliance Metadata Service 3 (MDS3) blob, for the
// three vendors stet's AAGUID table covers: Yubico, Google (Titan), and
// Feitian.
//
// It performs the verification the plan requires before trusting anything
// in the blob:
//  1. Fetches (or reads, via -blob) the JWT-signed MDS3 blob.
//  2. Verifies the JWT's x5c signing-certificate chain terminates at the
//     well-known GlobalSign Root R3 (embedded below, fingerprint checked at
//     runtime against the constant documented in both manifest.json and
//     aaguids.json).
//  3. Verifies the JWT's RS256 signature over its header+payload using the
//     leaf signing certificate's public key.
//
// Only then does it parse the payload's "entries" and extract, for every
// FIDO2 entry whose attestationRootCertificates chain to a Yubico, Titan or
// Feitian root (identified by certificate Subject, not by product-name
// string matching, which produced false positives such as "cryptovision
// ePasslet Suite" matching "epass" and Android's platform "Android
// Authenticator" entry matching "Google"):
//
//   - the AAGUID, vendor, description, and flattened userVerificationDetails
//     (excluding the "none" alternative, which every entry lists and which
//     carries no classification information);
//   - every attestationRootCertificates certificate, split into self-signed
//     roots (trust anchors) and non-self-signed intermediates (added to
//     VerifyOptions.Intermediates, never a trust anchor). Intermediates are
//     emitted in dependency order (parents before children) so
//     buildTrustStore's issuer_sha256 resolution succeeds even for
//     multi-level chains such as Yubico's Root 1 -> Intermediate A/B 1 ->
//     FIDO Attestation A/B(2) 1.
//
// The MDS endpoint rate-limits aggressively (HTTP 429); fetchBlob retries
// with linear backoff. If the blob can never be fetched or fails
// verification, this program exits non-zero rather than writing anything —
// it never fabricates entries.
//
// Usage:
//
//	go run ./scripts/gen-mds-aaguids [-blob path/to/cached.jwt] [-dry-run]
//
// Run from the repository root; it reads and writes internal/attest/.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// expectedGlobalSignR3SHA256 is the DER SHA-256 fingerprint of GlobalSign
// Root R3, documented identically in roots/manifest.json's titan-root.pem
// entry and metadata/aaguids.json's source block. It is checked at runtime
// against the embedded PEM below, so a corrupted or swapped embed is
// detected rather than silently trusted.
const expectedGlobalSignR3SHA256 = "cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b"

//go:embed globalsign-root-r3.pem
var globalSignR3PEM []byte

const mdsBlobURL = "https://mds3.fidoalliance.org/"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-mds-aaguids:", err)
		os.Exit(1)
	}
}

func run() error {
	blobPath := flag.String("blob", "", "path to a previously fetched MDS3 JWT blob; skips the network fetch")
	attestDir := flag.String("attest-dir", "internal/attest", "path to the internal/attest package directory")
	maxRetries := flag.Int("retries", 6, "max fetch attempts on HTTP 429 before giving up")
	dryRun := flag.Bool("dry-run", false, "verify and extract, print a summary, but write nothing")
	flag.Parse()

	var raw []byte
	var err error
	if *blobPath != "" {
		raw, err = os.ReadFile(*blobPath)
		if err != nil {
			return fmt.Errorf("reading -blob: %w", err)
		}
	} else {
		raw, err = fetchBlob(mdsBlobURL, *maxRetries)
		if err != nil {
			return fmt.Errorf("fetching MDS3 blob: %w", err)
		}
	}

	payload, err := verifyAndParse(raw)
	if err != nil {
		return fmt.Errorf("verifying MDS3 blob: %w", err)
	}

	extracted := extractVendorEntries(payload)
	fmt.Printf("MDS3 blob no. %d (nextUpdate %s): %d entries total, %d match Yubico/Titan/Feitian FIDO2\n",
		payload.No, payload.NextUpdate, len(payload.Entries), len(extracted.aaguids))
	fmt.Printf("  roots discovered:         %d\n", len(extracted.roots))
	fmt.Printf("  intermediates discovered: %d\n", len(extracted.intermediates))

	if *dryRun {
		return nil
	}

	return writeOutputs(*attestDir, payload, extracted)
}

// fetchBlob fetches url, retrying on HTTP 429 with linear backoff
// (attempt*15s) up to maxRetries times. It returns an error, never
// fabricated data, if every attempt fails.
func fetchBlob(url string, maxRetries int) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			time.Sleep(time.Duration(attempt-1) * 15 * time.Second)
		}
		resp, err := http.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("HTTP 429 (attempt %d/%d): %s", attempt, maxRetries, strings.TrimSpace(string(body)))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d (attempt %d/%d): %s", resp.StatusCode, attempt, maxRetries, strings.TrimSpace(string(body)))
			continue
		}
		if len(body) < 1000 {
			lastErr = fmt.Errorf("suspiciously short response (%d bytes) on attempt %d/%d", len(body), attempt, maxRetries)
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", maxRetries, lastErr)
}

// mdsPayload is the subset of the MDS3 blob's JWT payload this program
// needs.
type mdsPayload struct {
	No         int        `json:"no"`
	NextUpdate string     `json:"nextUpdate"`
	Entries    []mdsEntry `json:"entries"`
}

type mdsEntry struct {
	AAGUID            string           `json:"aaguid"`
	MetadataStatement *mdsMetadataStmt `json:"metadataStatement"`
}

type mdsMetadataStmt struct {
	Description                 string       `json:"description"`
	ProtocolFamily              string       `json:"protocolFamily"`
	AttestationRootCertificates []string     `json:"attestationRootCertificates"`
	UserVerificationDetails     [][]mdsUVAlt `json:"userVerificationDetails"`
}

type mdsUVAlt struct {
	UserVerificationMethod string `json:"userVerificationMethod"`
}

// verifyAndParse verifies raw as a JWT: its x5c chain must terminate at the
// embedded, fingerprint-checked GlobalSign Root R3, and its RS256 signature
// must verify against the leaf (x5c[0]) certificate's public key. Only then
// does it decode and return the payload.
func verifyAndParse(raw []byte) (*mdsPayload, error) {
	parts := strings.Split(strings.TrimSpace(string(raw)), ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: got %d dot-separated parts, want 3", len(parts))
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("decoding JWT header: %w", err)
	}
	var header struct {
		Alg string   `json:"alg"`
		Typ string   `json:"typ"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parsing JWT header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported JWT alg %q; this program only verifies RS256 (the alg the real MDS3 blob uses)", header.Alg)
	}
	if len(header.X5C) == 0 {
		return nil, errors.New("JWT header has no x5c signing chain")
	}

	certs := make([]*x509.Certificate, len(header.X5C))
	for i, b64 := range header.X5C {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d]: decoding base64: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d]: parsing certificate: %w", i, err)
		}
		certs[i] = cert
	}

	root, err := loadEmbeddedGlobalSignR3()
	if err != nil {
		return nil, err
	}

	// Verify each hop's signature: x5c is leaf-first, so certs[i] must be
	// signed by certs[i+1], up to whichever cert is (or chains to) the root.
	for i := 0; i < len(certs)-1; i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("x5c[%d] does not chain to x5c[%d]: %w", i, i+1, err)
		}
	}
	last := certs[len(certs)-1]
	if sha256Hex(last.Raw) != sha256Hex(root.Raw) {
		if err := last.CheckSignatureFrom(root); err != nil {
			return nil, fmt.Errorf("x5c chain does not terminate at GlobalSign Root R3: %w", err)
		}
	}

	leaf := certs[0]
	rsaKey, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("leaf signing certificate's public key is %T, want *rsa.PublicKey", leaf.PublicKey)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("decoding JWT signature: %w", err)
	}
	signingInput := headerB64 + "." + payloadB64
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("JWT signature does not verify against leaf certificate: %w", err)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}
	var payload mdsPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("parsing JWT payload: %w", err)
	}
	return &payload, nil
}

func loadEmbeddedGlobalSignR3() (*x509.Certificate, error) {
	block, _ := pem.Decode(globalSignR3PEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("embedded globalsign-root-r3.pem is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing embedded GlobalSign Root R3: %w", err)
	}
	got := sha256Hex(cert.Raw)
	if got != expectedGlobalSignR3SHA256 {
		return nil, fmt.Errorf("embedded GlobalSign Root R3 sha256 is %s, want %s (embed may have been tampered with)", got, expectedGlobalSignR3SHA256)
	}
	return cert, nil
}

// aaguidOut mirrors internal/attest's aaguidEntry JSON schema.
type aaguidOut struct {
	AAGUID      string   `json:"aaguid"`
	Vendor      string   `json:"vendor"`
	Description string   `json:"description"`
	RootSHA256  []string `json:"root_sha256"`
	UVMethods   []string `json:"uv_methods"`
}

// certOut is one certificate discovered in some entry's
// attestationRootCertificates.
type certOut struct {
	cert             *x509.Certificate
	sha256           string
	vendor           string
	selfSigned       bool
	issuerSHA        string // only meaningful when !selfSigned
	firstAAGUID      string
	firstDescription string
}

type extraction struct {
	aaguids       []aaguidOut
	roots         map[string]*certOut // sha256 -> cert, self-signed
	intermediates map[string]*certOut // sha256 -> cert, not self-signed
}

// vendorFromRootSubject identifies the vendor a root/intermediate
// certificate belongs to by inspecting its Subject, not the product's
// marketing name: matching on description text alone produced false
// positives (e.g. "cryptovision ePasslet Suite" contains "epass", and
// Android's platform attestation entry's description contains "Google").
func vendorFromRootSubject(cert *x509.Certificate) string {
	subj := cert.Subject.String()
	switch {
	case strings.Contains(subj, "Yubico"):
		return "Yubico"
	case strings.Contains(subj, "Titan"):
		return "Google"
	case strings.Contains(strings.ToLower(subj), "feitian"):
		return "Feitian"
	default:
		return ""
	}
}

func isSelfSignedCert(cert *x509.Certificate) bool {
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// extractVendorEntries walks every FIDO2 entry in payload and pulls out the
// AAGUID records plus every root/intermediate certificate for the three
// vendors this package covers.
func extractVendorEntries(payload *mdsPayload) *extraction {
	out := &extraction{
		roots:         map[string]*certOut{},
		intermediates: map[string]*certOut{},
	}

	for _, e := range payload.Entries {
		ms := e.MetadataStatement
		if ms == nil || ms.ProtocolFamily != "fido2" || e.AAGUID == "" {
			continue
		}

		certs := make([]*x509.Certificate, 0, len(ms.AttestationRootCertificates))
		for _, b64 := range ms.AttestationRootCertificates {
			der, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				continue // malformed; skip this one cert, not the whole entry
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
		}

		vendor := ""
		for _, cert := range certs {
			if v := vendorFromRootSubject(cert); v != "" {
				vendor = v
				break
			}
		}
		if vendor == "" {
			continue // not one of Yubico/Titan/Feitian
		}

		uvSet := map[string]bool{}
		for _, alt := range ms.UserVerificationDetails {
			for _, m := range alt {
				if m.UserVerificationMethod != "" && m.UserVerificationMethod != "none" {
					uvSet[m.UserVerificationMethod] = true
				}
			}
		}
		var uvMethods []string
		for m := range uvSet {
			uvMethods = append(uvMethods, m)
		}
		sort.Strings(uvMethods)

		var rootSHAs []string
		for _, cert := range certs {
			sha := sha256Hex(cert.Raw)
			if isSelfSignedCert(cert) {
				rootSHAs = append(rootSHAs, sha)
				if _, ok := out.roots[sha]; !ok {
					out.roots[sha] = &certOut{cert: cert, sha256: sha, vendor: vendor, selfSigned: true, firstAAGUID: e.AAGUID, firstDescription: ms.Description}
				}
			} else {
				if _, ok := out.intermediates[sha]; !ok {
					out.intermediates[sha] = &certOut{cert: cert, sha256: sha, vendor: vendor, selfSigned: false, firstAAGUID: e.AAGUID, firstDescription: ms.Description}
				}
			}
		}
		sort.Strings(rootSHAs)

		out.aaguids = append(out.aaguids, aaguidOut{
			AAGUID:      e.AAGUID,
			Vendor:      vendor,
			Description: ms.Description,
			RootSHA256:  rootSHAs,
			UVMethods:   uvMethods,
		})
	}

	resolveIssuers(out)

	sort.Slice(out.aaguids, func(i, j int) bool { return out.aaguids[i].AAGUID < out.aaguids[j].AAGUID })
	return out
}

// resolveIssuers sets issuerSHA on every intermediate in out by checking its
// signature against every root and every other intermediate. An
// intermediate whose issuer can't be resolved this way is left with an
// empty issuerSHA; writeOutputs refuses to emit a manifest with one.
func resolveIssuers(out *extraction) {
	candidates := make([]*certOut, 0, len(out.roots)+len(out.intermediates))
	for _, c := range out.roots {
		candidates = append(candidates, c)
	}
	for _, c := range out.intermediates {
		candidates = append(candidates, c)
	}

	for _, inter := range out.intermediates {
		for _, cand := range candidates {
			if cand.sha256 == inter.sha256 {
				continue
			}
			if inter.cert.CheckSignatureFrom(cand.cert) == nil {
				inter.issuerSHA = cand.sha256
				break
			}
		}
	}
}

func sha256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

var slugNonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.ToLower(s)
	s = slugNonAlnum.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// --- manifest/aaguids schema mirrors (kept in sync with internal/attest/roots.go) ---

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

type aaguidMetadata struct {
	Version int             `json:"version"`
	Source  json.RawMessage `json:"source"`
	Entries []aaguidOut     `json:"entries"`
}

// writeOutputs reconciles the newly extracted data against what's already
// on disk under attestDir (preserving existing roots/manifest entries and
// filenames byte-for-byte when their sha256 is unchanged), writes any new
// roots/*.pem files, and rewrites roots/manifest.json and
// metadata/aaguids.json.
func writeOutputs(attestDir string, payload *mdsPayload, ex *extraction) error {
	rootsDir := filepath.Join(attestDir, "roots")
	manifestPath := filepath.Join(rootsDir, "manifest.json")
	aaguidsPath := filepath.Join(attestDir, "metadata", "aaguids.json")

	var manifest rootManifest
	if b, err := os.ReadFile(manifestPath); err == nil {
		if err := json.Unmarshal(b, &manifest); err != nil {
			return fmt.Errorf("parsing existing %s: %w", manifestPath, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if manifest.Version < 1 {
		manifest.Version = 1
	}

	taken := map[string]bool{}
	existingRootBySHA := map[string]rootManifestEntry{}
	for _, r := range manifest.Roots {
		taken[r.File] = true
		existingRootBySHA[strings.ToLower(r.SHA256)] = r
	}
	existingInterBySHA := map[string]intermediateManifestEntry{}
	for _, in := range manifest.Intermediates {
		taken[in.File] = true
		existingInterBySHA[strings.ToLower(in.SHA256)] = in
	}

	today := time.Now().UTC().Format("2006-01-02")
	newPEMs := map[string][]byte{}

	// Reconcile roots: keep existing entries verbatim (by sha256), append
	// any newly discovered root sorted by sha256 for determinism.
	var newRootSHAs []string
	for sha := range ex.roots {
		if _, ok := existingRootBySHA[sha]; !ok {
			newRootSHAs = append(newRootSHAs, sha)
		}
	}
	sort.Strings(newRootSHAs)

	fileBySHA := map[string]string{}
	for sha, r := range existingRootBySHA {
		fileBySHA[sha] = r.File
	}

	for _, sha := range newRootSHAs {
		c := ex.roots[sha]
		name := uniqueName("", c.cert, taken)
		fileBySHA[sha] = name
		newPEMs[name] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
		manifest.Roots = append(manifest.Roots, rootManifestEntry{
			File:                name,
			Vendor:              c.vendor,
			Subject:             c.cert.Subject.String(),
			SHA256:              sha,
			NotAfter:            c.cert.NotAfter.UTC().Format(time.RFC3339),
			SourceURL:           mdsBlobURL,
			Retrieved:           today,
			CrossCheckedAgainst: fmt.Sprintf("FIDO MDS3 blob no. %d (mds3.fidoalliance.org), attestationRootCertificates of AAGUID %s (%s)", payload.No, c.firstAAGUID, c.firstDescription),
		})
	}

	// Reconcile intermediates: process in dependency order (parents before
	// children) so every issuer_sha256 resolves to something already
	// listed, matching what buildTrustStore requires.
	ordered := orderIntermediates(ex.intermediates, fileBySHA)
	newIntermediateCount := 0
	for _, sha := range ordered {
		if _, ok := existingInterBySHA[sha]; ok {
			fileBySHA[sha] = existingInterBySHA[sha].File
			continue
		}
		c := ex.intermediates[sha]
		if c.issuerSHA == "" {
			return fmt.Errorf("intermediate %s (%s) has no resolvable issuer among bundled roots/intermediates; refusing to emit an unverifiable entry", sha, c.cert.Subject.String())
		}
		if _, ok := fileBySHA[c.issuerSHA]; !ok {
			return fmt.Errorf("intermediate %s: issuer %s not yet assigned a file (dependency ordering bug)", sha, c.issuerSHA)
		}
		newIntermediateCount++
		name := uniqueName("", c.cert, taken)
		fileBySHA[sha] = name
		newPEMs[name] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
		manifest.Intermediates = append(manifest.Intermediates, intermediateManifestEntry{
			File:                name,
			Vendor:              c.vendor,
			Subject:             c.cert.Subject.String(),
			SHA256:              sha,
			IssuerSHA256:        c.issuerSHA,
			NotAfter:            c.cert.NotAfter.UTC().Format(time.RFC3339),
			SourceURL:           mdsBlobURL,
			Retrieved:           today,
			CrossCheckedAgainst: fmt.Sprintf("FIDO MDS3 blob no. %d (mds3.fidoalliance.org), attestationRootCertificates of AAGUID %s (%s)", payload.No, c.firstAAGUID, c.firstDescription),
		})
	}

	if err := os.MkdirAll(rootsDir, 0o755); err != nil {
		return err
	}
	for name, data := range newPEMs {
		if err := os.WriteFile(filepath.Join(rootsDir, name), data, 0o644); err != nil {
			return err
		}
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(manifestPath, append(manifestJSON, '\n'), 0o644); err != nil {
		return err
	}

	sourceJSON, err := json.Marshal(map[string]any{
		"mds3_blob_no": payload.No,
		"next_update":  payload.NextUpdate,
		"retrieved":    today,
		"url":          mdsBlobURL,
		"jwt_verified_to": fmt.Sprintf(
			"GlobalSign Root R3 (sha256 %s, fetched from http://secure.globalsign.com/cacert/root-r3.crt)",
			colonize(expectedGlobalSignR3SHA256),
		),
	})
	if err != nil {
		return err
	}
	aaguidsOut := aaguidMetadata{Version: 1, Source: sourceJSON, Entries: ex.aaguids}
	aaguidsJSON, err := json.MarshalIndent(aaguidsOut, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(aaguidsPath, append(aaguidsJSON, '\n'), 0o644); err != nil {
		return err
	}

	fmt.Printf("wrote %d new root PEM(s), %d new intermediate PEM(s), %s, %s\n",
		len(newRootSHAs), newIntermediateCount, manifestPath, aaguidsPath)
	return nil
}

// orderIntermediates topologically sorts intermediates (by sha256) so every
// entry appears after whatever it's ultimately issued by, resolving against
// both roots (via fileBySHA, which is seeded with every root) and other
// intermediates.
func orderIntermediates(intermediates map[string]*certOut, rootFileBySHA map[string]string) []string {
	resolved := map[string]bool{}
	for sha := range rootFileBySHA {
		resolved[sha] = true
	}
	var order []string
	remaining := make(map[string]*certOut, len(intermediates))
	for sha, c := range intermediates {
		remaining[sha] = c
	}
	for len(remaining) > 0 {
		progress := false
		var shas []string
		for sha := range remaining {
			shas = append(shas, sha)
		}
		sort.Strings(shas)
		for _, sha := range shas {
			c := remaining[sha]
			if c.issuerSHA != "" && resolved[c.issuerSHA] {
				order = append(order, sha)
				resolved[sha] = true
				delete(remaining, sha)
				progress = true
			}
		}
		if !progress {
			// Whatever's left has an unresolvable or cyclic issuer; append
			// it anyway in deterministic order so writeOutputs' explicit
			// issuerSHA=="" / unresolved check reports it clearly instead
			// of this function silently dropping it.
			for _, sha := range shas {
				order = append(order, sha)
				delete(remaining, sha)
			}
		}
	}
	return order
}

// colonize renders a lowercase hex fingerprint as colon-separated byte pairs
// ("cbb522..." -> "cb:b5:22:..."), matching the style already used in
// manifest.json and aaguids.json.
func colonize(hexStr string) string {
	var b strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexStr[i : i+2])
	}
	return b.String()
}

// uniqueName allocates a filesystem-safe .pem filename for cert, deriving a
// slug from its CommonName and disambiguating with country/year/fingerprint
// suffixes against the taken set (which it mutates).
func uniqueName(_ string, cert *x509.Certificate, taken map[string]bool) string {
	base := slugify(cert.Subject.CommonName)
	if base == "" {
		base = "cert"
	}
	candidates := []string{base}
	if len(cert.Subject.Country) > 0 {
		candidates = append(candidates, base+"-"+strings.ToLower(cert.Subject.Country[0]))
	}
	candidates = append(candidates, fmt.Sprintf("%s-%d", base, cert.NotAfter.Year()))
	if len(cert.Subject.Country) > 0 {
		candidates = append(candidates, fmt.Sprintf("%s-%s-%d", base, strings.ToLower(cert.Subject.Country[0]), cert.NotAfter.Year()))
	}
	fp := sha256Hex(cert.Raw)
	candidates = append(candidates, base+"-"+fp[:8])

	for _, c := range candidates {
		name := c + ".pem"
		if !taken[name] {
			taken[name] = true
			return name
		}
	}
	// Exhausted every heuristic; fall back to the full fingerprint, which is
	// unique by construction.
	name := base + "-" + fp + ".pem"
	taken[name] = true
	return name
}
