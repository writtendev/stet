// Package fidotest provides a pure-Go software authenticator implementing
// fido.Authenticator, for tests that need a working CTAP2 device without
// real hardware or libfido2. It is used by this repo's own fido and trust
// tests, and is meant to be reused by STET-3 (write path) and STET-10
// (enrollment ceremony) tests too.
package fidotest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"sync"

	"github.com/writtendev/stet/internal/fido"
)

// DevicePath is the virtual device path Soft reports from Devices, and the
// only devicePath its MakeCredential/GetAssertion accept.
const DevicePath = "fidotest://soft"

// Options configures a Soft authenticator's behavior.
type Options struct {
	// Rand supplies randomness for key generation, credential IDs and
	// ECDSA signing. Defaults to crypto/rand.Reader; set it to a fixed
	// source (e.g. a seeded math/rand-backed io.Reader) for deterministic
	// tests.
	Rand io.Reader

	// UserPresent and UserVerified set the corresponding authData flags
	// on every credential and assertion this authenticator produces.
	UserPresent  bool
	UserVerified bool

	// PIN is the PIN configured on the virtual device. Empty means no PIN
	// is set. A request that supplies a non-empty PIN not matching this
	// value fails with fido.ErrPINInvalid, mirroring the real backend.
	PIN string

	// FailWith, when non-nil, is returned by every call instead of doing
	// anything, to simulate an arbitrary device failure.
	FailWith error

	// NoDevices, when true, makes Devices report no devices and
	// MakeCredential/GetAssertion fail with fido.ErrNoDevice.
	NoDevices bool
}

// Soft is a software CTAP2 authenticator: one virtual device backed by
// in-memory ES256 keypairs. It implements fido.Authenticator.
type Soft struct {
	opts Options

	mu         sync.Mutex
	keys       map[string]*ecdsa.PrivateKey
	signCounts map[string]uint32
}

// NewSoft constructs a Soft authenticator with the given options.
func NewSoft(opts Options) *Soft {
	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}
	return &Soft{
		opts:       opts,
		keys:       make(map[string]*ecdsa.PrivateKey),
		signCounts: make(map[string]uint32),
	}
}

// Devices reports the one virtual device, unless NoDevices is set.
func (s *Soft) Devices(ctx context.Context) ([]fido.DeviceInfo, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if s.opts.FailWith != nil {
		return nil, s.opts.FailWith
	}
	if s.opts.NoDevices {
		return nil, nil
	}
	return []fido.DeviceInfo{{
		Path:         DevicePath,
		Manufacturer: "stet",
		Product:      "fidotest software authenticator",
	}}, nil
}

// MakeCredential generates an ES256 keypair and returns a Credential with
// real authenticatorData: rpIdHash, flags, a zero signCount, and attested
// credential data carrying a hand-encoded COSE EC2 key. The attestation
// format is "none" (AttStmt is the empty-CBOR-map byte {0xa0}).
func (s *Soft) MakeCredential(ctx context.Context, devicePath string, req fido.CredentialRequest) (*fido.Credential, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if s.opts.FailWith != nil {
		return nil, s.opts.FailWith
	}
	if s.opts.NoDevices || devicePath != DevicePath {
		return nil, fido.ErrNoDevice
	}
	if req.RequireUV && req.PIN == "" {
		return nil, fido.ErrPINRequired
	}
	if err := s.checkPIN(req.PIN); err != nil {
		return nil, err
	}

	alg := req.Algorithm
	if alg == 0 {
		alg = fido.ES256
	}
	if alg != fido.ES256 {
		return nil, fido.ErrUnsupportedAlgorithm
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), s.opts.Rand)
	if err != nil {
		return nil, err
	}

	credID := make([]byte, 16)
	if _, err := io.ReadFull(s.opts.Rand, credID); err != nil {
		return nil, err
	}

	var aaguid [16]byte
	copy(aaguid[:], []byte("stet-fidotestsw!"))

	coseKey := encodeCOSEEC2Key(priv.X, priv.Y)
	flags := flagsByte(s.opts.UserPresent, s.opts.UserVerified, true)
	authData := buildAuthData(req.RPID, flags, 0, &aaguid, credID, coseKey)

	pkixKey, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.keys[string(credID)] = priv
	s.mu.Unlock()

	return &fido.Credential{
		Format:         "none",
		AuthData:       authData,
		AttStmt:        []byte{0xa0},
		ClientDataHash: req.ClientDataHash,
		CredentialID:   credID,
		AAGUID:         aaguid,
		Algorithm:      alg,
		PublicKey:      pkixKey,
		Flags: fido.Flags{
			UserPresent:            s.opts.UserPresent,
			UserVerified:           s.opts.UserVerified,
			AttestedCredentialData: true,
		},
	}, nil
}

// GetAssertion signs over authData || clientDataHash with the private key
// for the first of req.CredentialIDs this authenticator holds.
func (s *Soft) GetAssertion(ctx context.Context, devicePath string, req fido.AssertionRequest) (*fido.Assertion, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if s.opts.FailWith != nil {
		return nil, s.opts.FailWith
	}
	if s.opts.NoDevices || devicePath != DevicePath {
		return nil, fido.ErrNoDevice
	}
	if req.RequireUV && req.PIN == "" {
		return nil, fido.ErrPINRequired
	}
	if err := s.checkPIN(req.PIN); err != nil {
		return nil, err
	}

	s.mu.Lock()
	var priv *ecdsa.PrivateKey
	var credID []byte
	for _, id := range req.CredentialIDs {
		if k, ok := s.keys[string(id)]; ok {
			priv, credID = k, id
			break
		}
	}
	s.mu.Unlock()
	if priv == nil {
		return nil, fido.ErrNoCredentials
	}

	signCount := s.nextSignCount(credID)
	flags := flagsByte(s.opts.UserPresent, s.opts.UserVerified, false)
	authData := buildAuthData(req.RPID, flags, signCount, nil, nil, nil)

	signed := make([]byte, 0, len(authData)+len(req.ClientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, req.ClientDataHash[:]...)
	digest := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(s.opts.Rand, priv, digest[:])
	if err != nil {
		return nil, err
	}

	return &fido.Assertion{
		AuthData:       authData,
		Signature:      sig,
		CredentialID:   credID,
		ClientDataHash: req.ClientDataHash,
		SignCount:      signCount,
		Flags: fido.Flags{
			UserPresent:  s.opts.UserPresent,
			UserVerified: s.opts.UserVerified,
		},
	}, nil
}

func (s *Soft) checkPIN(reqPIN string) error {
	if reqPIN == "" {
		return nil
	}
	if s.opts.PIN == "" || reqPIN != s.opts.PIN {
		return fido.ErrPINInvalid
	}
	return nil
}

func (s *Soft) nextSignCount(credID []byte) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(credID)
	s.signCounts[key]++
	return s.signCounts[key]
}

func ctxErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fido.ErrCancelled
	default:
		return nil
	}
}

const (
	flagUserPresent            = 1 << 0
	flagUserVerified           = 1 << 2
	flagAttestedCredentialData = 1 << 6
)

func flagsByte(userPresent, userVerified, attested bool) byte {
	var b byte
	if userPresent {
		b |= flagUserPresent
	}
	if userVerified {
		b |= flagUserVerified
	}
	if attested {
		b |= flagAttestedCredentialData
	}
	return b
}

// buildAuthData assembles a raw (unwrapped) authenticatorData buffer. When
// aaguid is non-nil, attested credential data (aaguid, credential ID
// length + ID, and the raw COSE public key) is appended.
func buildAuthData(rpID string, flags byte, signCount uint32, aaguid *[16]byte, credID, coseKey []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))

	buf := make([]byte, 0, 37+16+2+len(credID)+len(coseKey))
	buf = append(buf, rpHash[:]...)
	buf = append(buf, flags)

	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	buf = append(buf, sc[:]...)

	if aaguid != nil {
		buf = append(buf, aaguid[:]...)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(credID)))
		buf = append(buf, l[:]...)
		buf = append(buf, credID...)
		buf = append(buf, coseKey...)
	}
	return buf
}

// encodeCOSEEC2Key hand-encodes a COSE_Key CBOR map for an EC2 P-256 key:
// {1: 2, 3: -7, -1: 1, -2: bstr(x), -3: bstr(y)} (kty=EC2, alg=ES256,
// crv=P-256).
func encodeCOSEEC2Key(x, y *big.Int) []byte {
	xb := make([]byte, 32)
	x.FillBytes(xb)
	yb := make([]byte, 32)
	y.FillBytes(yb)

	buf := []byte{0xa5}                 // map, 5 pairs
	buf = append(buf, 0x01, 0x02)       // kty: EC2 (2)
	buf = append(buf, 0x03, 0x26)       // alg: ES256 (-7)
	buf = append(buf, 0x20, 0x01)       // crv: P-256 (1)
	buf = append(buf, 0x21, 0x58, 0x20) // x: bstr(32)
	buf = append(buf, xb...)
	buf = append(buf, 0x22, 0x58, 0x20) // y: bstr(32)
	buf = append(buf, yb...)
	return buf
}
