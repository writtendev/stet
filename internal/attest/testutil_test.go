package attest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ---------------------------------------------------------------------------
// Synthetic test-only CA. Generated fresh per test process, never written to
// disk, never added to the embedded trust store: this is exactly the
// "test-only CA generated at runtime" the STET-6 plan calls for, used only
// through the unexported verify(), never through the exported Verify().
// ---------------------------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "stet synthetic test root (never trusted in production)"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating test CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing test CA cert: %v", err)
	}
	return &testCA{cert: cert, key: key, der: der}
}

// buildTrustStore builds a trustStore whose only root is this test CA, and
// whose AAGUID table is aaguidJSON (metadata/aaguids.json's schema).
// Vendor is recorded as "TestVendor".
func (ca *testCA) buildTrustStore(t *testing.T, aaguidJSON []byte) *trustStore {
	t.Helper()

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
	manifest := rootManifest{
		Version: 999,
		Roots: []rootManifestEntry{{
			File:   "test-root.pem",
			Vendor: "TestVendor",
			SHA256: sha256Hex(ca.der),
		}},
	}
	ts, err := buildTrustStore(map[string][]byte{"test-root.pem": pemBytes}, manifest, aaguidJSON)
	if err != nil {
		t.Fatalf("building test trust store: %v", err)
	}
	return ts
}

func aaguidJSONFor(entries ...aaguidEntry) []byte {
	meta := aaguidMetadata{Version: 1, Entries: entries}
	b, err := json.Marshal(meta)
	if err != nil {
		panic(err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Leaf certificate construction.
// ---------------------------------------------------------------------------

type keyKind int

const (
	keyP256 keyKind = iota
	keyP384
	keyEd25519
	keyRSA2048
)

func generateKey(t *testing.T, kind keyKind) (pub crypto.PublicKey, signer crypto.Signer) {
	t.Helper()
	switch kind {
	case keyP256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &k.PublicKey, k
	case keyP384:
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &k.PublicKey, k
	case keyEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub, priv
	case keyRSA2048:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return &k.PublicKey, k
	}
	panic("unreachable")
}

// aaguidExtSpec controls how the id-fido-gen-ce-aaguid extension is written
// onto a synthetic leaf certificate, so tests can produce every malformed
// shape the algorithm needs to reject.
type aaguidExtSpec struct {
	absent    bool
	critical  bool
	content   []byte // defaults to the leaf's matching AAGUID if nil and !absent
	trailing  bool   // append garbage bytes after a valid OCTET STRING enccoding
	rawOctets int    // if >0, override content length with this many zero bytes
}

func encodeAAGUIDExtValue(t *testing.T, spec aaguidExtSpec, aaguid [16]byte) []byte {
	t.Helper()
	content := spec.content
	if content == nil {
		content = aaguid[:]
	}
	if spec.rawOctets > 0 {
		content = make([]byte, spec.rawOctets)
	}
	val, err := asn1.Marshal(content) // asn1.Marshal([]byte) => OCTET STRING
	if err != nil {
		t.Fatal(err)
	}
	if spec.trailing {
		val = append(val, 0xDE, 0xAD)
	}
	return val
}

// leafSpec configures a synthetic packed-attestation leaf certificate.
type leafSpec struct {
	subject     pkix.Name // zero value fills in a valid default
	isCA        bool
	keyKind     keyKind
	aaguid      [16]byte
	aaguidExt   *aaguidExtSpec // nil => a correct, matching, non-critical extension
	selfSigned  bool           // sign with the leaf's own key instead of ca's
	notBefore   time.Time
	notAfter    time.Time
	extraSerial int64
}

func defaultLeafSubject() pkix.Name {
	return pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"stet test"},
		OrganizationalUnit: []string{requiredLeafOU},
		CommonName:         "stet synthetic test leaf",
	}
}

// buildLeaf creates a synthetic packed-attestation leaf certificate signed
// by ca (or self-signed, if spec.selfSigned), returning its DER encoding
// and its private key.
func buildLeaf(t *testing.T, ca *testCA, spec leafSpec) ([]byte, crypto.Signer) {
	t.Helper()

	subject := spec.subject

	notBefore := spec.notBefore
	if notBefore.IsZero() {
		notBefore = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	notAfter := spec.notAfter
	if notAfter.IsZero() {
		notAfter = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	serial := spec.extraSerial
	if serial == 0 {
		serial = 2
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  spec.isCA,
	}
	if spec.isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}

	if spec.aaguidExt == nil || !spec.aaguidExt.absent {
		var extSpec aaguidExtSpec
		if spec.aaguidExt != nil {
			extSpec = *spec.aaguidExt
		}
		value := encodeAAGUIDExtValue(t, extSpec, spec.aaguid)
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:       oidFIDOGenCEAAGUID,
			Critical: extSpec.critical,
			Value:    value,
		})
	}

	pub, signer := generateKey(t, spec.keyKind)

	var (
		parentTmpl *x509.Certificate
		parentKey  crypto.Signer
	)
	if spec.selfSigned {
		parentTmpl = tmpl
		parentKey = signer
	} else {
		parentTmpl = ca.cert
		parentKey = ca.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentTmpl, pub, parentKey)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	return der, signer
}

// forceCertVersion patches the ASN.1 version field on a freshly-created v3
// certificate's DER encoding to encode a different version number,
// in place, without touching anything else in the TBS structure (so the
// resulting bytes are shorter/longer by exactly zero -- only the version
// INTEGER's value byte changes). x509.CreateCertificate always emits the
// pattern A0 03 02 01 02 (context tag 0, INTEGER, value 2 == v3) as the
// first element of tbsCertificate; this is unreachable via the stdlib API
// otherwise, so tests that need a non-v3 leaf patch it directly.
func forceCertVersion(t *testing.T, der []byte, version byte) []byte {
	t.Helper()
	pattern := []byte{0xA0, 0x03, 0x02, 0x01, 0x02}
	idx := bytes.Index(der, pattern)
	if idx < 0 {
		t.Fatal("forceCertVersion: version pattern not found in DER")
	}
	out := append([]byte(nil), der...)
	out[idx+4] = version
	return out
}

// ---------------------------------------------------------------------------
// authData construction.
// ---------------------------------------------------------------------------

// buildAuthData assembles raw authenticatorData bytes for a make-credential
// attestation: rpIdHash | flags | signCount | aaguid | credIdLen | credId |
// COSE key | [extensions]. The COSE key and extensions payloads are
// arbitrary-but-valid CBOR items: Verify never inspects their content,
// only their well-formedness and length.
func buildAuthData(t *testing.T, rpID string, up, uv, ed bool, aaguid [16]byte, credID []byte) []byte {
	t.Helper()

	flags := byte(0)
	if up {
		flags |= flagUP
	}
	if uv {
		flags |= flagUV
	}
	flags |= flagAT
	if ed {
		flags |= flagED
	}

	rpIDHash := sha256.Sum256([]byte(rpID))

	buf := new(bytes.Buffer)
	buf.Write(rpIDHash[:])
	buf.WriteByte(flags)
	if err := binary.Write(buf, binary.BigEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	buf.Write(aaguid[:])
	if err := binary.Write(buf, binary.BigEndian, uint16(len(credID))); err != nil {
		t.Fatal(err)
	}
	buf.Write(credID)

	coseKey, err := cbor.Marshal(map[int]int{1: 2, 3: -7})
	if err != nil {
		t.Fatal(err)
	}
	buf.Write(coseKey)

	if ed {
		extMap, err := cbor.Marshal(map[string]int{"stet-test-extension": 1})
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(extMap)
	}

	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Packed attStmt signing.
// ---------------------------------------------------------------------------

// signPackedMessage signs message with signer under alg, returning the raw
// signature bytes as they belong in a packed attStmt's "sig" field.
func signPackedMessage(t *testing.T, signer crypto.Signer, alg int64, message []byte) []byte {
	t.Helper()

	switch alg {
	case algES256:
		h := sha256.Sum256(message)
		sig, err := ecdsa.SignASN1(rand.Reader, signer.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case algES384:
		h := sha512.Sum384(message)
		sig, err := ecdsa.SignASN1(rand.Reader, signer.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case algEdDSA:
		return ed25519.Sign(signer.(ed25519.PrivateKey), message)
	case algRS256:
		h := sha256.Sum256(message)
		sig, err := rsa.SignPKCS1v15(rand.Reader, signer.(*rsa.PrivateKey), crypto.SHA256, h[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig
	default:
		t.Fatalf("signPackedMessage: unsupported alg %d", alg)
		return nil
	}
}

// marshalAttestationObjectForTest builds a full CBOR
// {fmt, authData, attStmt} attestation object from its parts, the inverse
// of what ParseAttestationObject consumes.
func marshalAttestationObjectForTest(t *testing.T, format string, authData, attStmt []byte) ([]byte, error) {
	t.Helper()
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(rawAttestationObject{
		Fmt:      format,
		AuthData: authData,
		AttStmt:  cbor.RawMessage(attStmt),
	})
}
