// Package fido defines stet's boundary to CTAP2 hardware security keys.
//
// This package is pure Go: it builds with or without cgo. It declares the
// [Authenticator] interface and the credential/assertion types that flow
// across it, parses authenticator data, and verifies assertions against a
// public key. The libfido2 cgo backend (build tag "cgo && libfido2") and the
// unsupported stub (build tag "!(cgo && libfido2)") are the only two callers
// permitted to construct an Authenticator; everything else in this repo,
// including tests, talks to the interface.
//
// A software authenticator for tests lives in the sibling fidotest package.
//
// This package assigns no attestation trust class and parses no attestation
// statement — it hands [Credential.Format], [Credential.AttStmt],
// [Credential.AuthData] and friends to the caller untouched. Neither
// MakeCredential nor GetAssertion nor VerifyAssertion makes a network call;
// libfido2 talks only to local USB/NFC HID devices.
package fido

import (
	"context"
	"errors"
)

// COSEAlgorithm identifies a COSE signature algorithm by its registered
// integer identifier.
type COSEAlgorithm int

const (
	// ES256 is ECDSA over the P-256 curve with SHA-256, COSE algorithm -7.
	// It is the effective default: a zero-valued CredentialRequest's
	// Algorithm field is treated as ES256.
	ES256 COSEAlgorithm = -7
	// EdDSA is Ed25519, COSE algorithm -8.
	EdDSA COSEAlgorithm = -8
)

// DefaultRPID is the relying party identifier stet uses when none is given.
const DefaultRPID = "stet"

// Sentinel errors returned by Authenticator implementations. Wrap with
// errors.Is; backends must map their native error codes onto these.
var (
	// ErrUnsupported is returned by the stub backend, or by the libfido2
	// backend for an operation it cannot perform.
	ErrUnsupported = errors.New("fido2: unsupported")
	// ErrNoDevice is returned when no authenticator is present, or the
	// device path could not be opened or communicated with.
	ErrNoDevice = errors.New("fido2: no device")
	// ErrNotFIDO2 is returned when a device only speaks CTAP1/U2F. stet
	// does not fall back to U2F.
	ErrNotFIDO2 = errors.New("fido2: device is not CTAP2 (U2F-only, unsupported)")
	// ErrPINRequired is returned when user verification was required but
	// no PIN was supplied.
	ErrPINRequired = errors.New("fido2: PIN required")
	// ErrPINInvalid is returned when the supplied PIN was rejected by the
	// authenticator.
	ErrPINInvalid = errors.New("fido2: PIN invalid")
	// ErrActionTimeout is returned when the user did not touch the
	// authenticator in time.
	ErrActionTimeout = errors.New("fido2: timed out waiting for user action")
	// ErrOperationDenied is returned when the authenticator refused the
	// operation.
	ErrOperationDenied = errors.New("fido2: operation denied")
	// ErrNoCredentials is returned when none of the requested credential
	// IDs are recognized by the authenticator.
	ErrNoCredentials = errors.New("fido2: no matching credentials")
	// ErrUnsupportedAlgorithm is returned when the requested COSE
	// algorithm is not supported by the authenticator.
	ErrUnsupportedAlgorithm = errors.New("fido2: unsupported algorithm")
	// ErrCancelled is returned when the calling context was cancelled
	// while an operation was in flight.
	ErrCancelled = errors.New("fido2: cancelled")
)

// DeviceInfo describes a discovered authenticator.
type DeviceInfo struct {
	Path         string
	Manufacturer string
	Product      string
	VendorID     int16
	ProductID    int16
}

// Flags reports the CTAP2 authenticator data flags relevant to stet.
type Flags struct {
	UserPresent            bool
	UserVerified           bool
	AttestedCredentialData bool
}

// CredentialRequest parameters a CTAP2 make-credential call.
type CredentialRequest struct {
	RPID           string
	RPName         string
	UserID         []byte
	UserName       string
	ClientDataHash [32]byte
	// Algorithm selects the COSE algorithm. The zero value selects ES256.
	Algorithm COSEAlgorithm
	// PIN is submitted for user verification. Empty means UV is not
	// attempted.
	PIN string
	// RequireUV requests user verification. RequireUV set with an empty
	// PIN returns ErrPINRequired before the device is touched.
	RequireUV bool
}

// Credential is the result of a successful make-credential call.
type Credential struct {
	// Format is the attestation statement format (fido_cred_fmt), e.g.
	// "packed" or "none".
	Format string
	// AuthData is the raw authenticatorData, with the CBOR byte-string
	// wrapper libfido2 returns it in already stripped.
	AuthData []byte
	// AttStmt is the raw CBOR attestation statement map, exactly as
	// returned by the authenticator. STET-6 parses x5c/sig from this.
	AttStmt        []byte
	ClientDataHash [32]byte
	CredentialID   []byte
	AAGUID         [16]byte
	Algorithm      COSEAlgorithm
	// PublicKey is PKIX DER, converted from libfido2's raw x||y (ES256) or
	// raw 32-byte (EdDSA) key material.
	PublicKey []byte
	Flags     Flags
}

// AssertionRequest parameters a CTAP2 get-assertion call.
type AssertionRequest struct {
	RPID           string
	ClientDataHash [32]byte
	// CredentialIDs is the allow list of acceptable credentials. It is
	// required: this package does not request discoverable/resident
	// credentials.
	CredentialIDs [][]byte
	PIN           string
	RequireUV     bool
}

// Assertion is the result of a successful get-assertion call.
type Assertion struct {
	// AuthData is the raw, unwrapped authenticatorData.
	AuthData []byte
	// Signature is DER-encoded ECDSA for ES256, or a raw 64-byte
	// signature for EdDSA.
	Signature      []byte
	CredentialID   []byte
	ClientDataHash [32]byte
	SignCount      uint32
	Flags          Flags
}

// Authenticator is stet's boundary to a CTAP2 hardware security key. The
// libfido2 backend and the fidotest software authenticator both implement
// it; callers should depend only on this interface.
type Authenticator interface {
	// Devices enumerates connected authenticators.
	Devices(ctx context.Context) ([]DeviceInfo, error)
	// MakeCredential performs a CTAP2 make-credential ceremony against the
	// device at devicePath. It always requires user presence (touch).
	MakeCredential(ctx context.Context, devicePath string, req CredentialRequest) (*Credential, error)
	// GetAssertion performs a CTAP2 get-assertion ceremony against the
	// device at devicePath. It always requires user presence (touch).
	GetAssertion(ctx context.Context, devicePath string, req AssertionRequest) (*Assertion, error)
}
