// Package trust implements stet's local "bring-your-own-key" (BYOK) trust
// list: an append-only JSONL log of hardware public keys a repository (or
// user) has chosen to trust, plus revocations. It is fully offline — the
// log is a local file, and lookups never leave the machine.
//
// The log itself (Log) is a dumb append-only writer: Add and Revoke each
// write one record and fsync, with no knowledge of the file's cumulative
// state. Loading the file (Load) replays every record in order and is
// where inconsistency is caught: a duplicate add, an add of a
// previously-revoked credential, a revoke of an unknown credential, or an
// unrecognized op are all load errors. There is no delete or rewrite API;
// a mistaken add is corrected by revoking it, never by editing the file.
//
// Entries do not carry a hardware attestation trust class (e.g. "YubiKey
// series 5" vs "unknown"); that classification is STET-6's decision, made
// from the attestation statement at enrollment time, not stored here.
package trust

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/writtendev/stet/internal/fido"
)

// ErrUntrustedKey is returned by (*Set).VerifyAssertion when the
// assertion's credential is not present in the trust list at all.
var ErrUntrustedKey = fmt.Errorf("trust: credential is not in the trusted key list")

// ErrRevokedKey is returned by (*Set).VerifyAssertion when the assertion's
// credential was trusted but has since been revoked.
var ErrRevokedKey = fmt.Errorf("trust: credential has been revoked")

// Entry is a public key to append to the trust log via (*Log).Add.
type Entry struct {
	CredentialID []byte
	// PublicKey is PKIX DER, as produced by the fido package.
	PublicKey []byte
	Algorithm fido.COSEAlgorithm
	RPID      string
	AAGUID    [16]byte
	Label     string
}

// Key is a trusted public key as read back from the trust log.
type Key struct {
	CredentialID []byte
	PublicKey    []byte
	Algorithm    fido.COSEAlgorithm
	RPID         string
	AAGUID       [16]byte
	Label        string
	AddedAt      time.Time
}

// State is a credential's trust state within a Set.
type State int

const (
	// StateUnknown means the credential has never been added.
	StateUnknown State = iota
	// StateActive means the credential is trusted.
	StateActive
	// StateRevoked means the credential was trusted and has been
	// revoked.
	StateRevoked
)

// String renders State as "active", "revoked" or "unknown".
func (s State) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// DefaultPath returns the default location of the trust log:
// os.UserConfigDir()/stet/trusted-keys.jsonl.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("trust: %w", err)
	}
	return filepath.Join(dir, "stet", "trusted-keys.jsonl"), nil
}

// on-disk record shapes. Field order is the struct's declaration order,
// which is what makes json.Marshal's output stable line to line.

type addRecord struct {
	Op           string `json:"op"`
	CredentialID string `json:"credential_id"`
	PublicKey    string `json:"public_key"`
	Alg          string `json:"alg"`
	RPID         string `json:"rp_id"`
	AAGUID       string `json:"aaguid"`
	Label        string `json:"label"`
	At           string `json:"at"`
}

type revokeRecord struct {
	Op           string `json:"op"`
	CredentialID string `json:"credential_id"`
	Reason       string `json:"reason"`
	At           string `json:"at"`
}

type opHeader struct {
	Op string `json:"op"`
}

// Log is an append-only writer for the trust log file.
type Log struct {
	mu    sync.Mutex
	f     *os.File
	clock func() time.Time
}

// Option configures a Log opened with Open.
type Option func(*Log)

// WithClock overrides the clock used to stamp new records' "at" field.
// Tests use this for deterministic output; production code should leave
// it unset (time.Now).
func WithClock(clock func() time.Time) Option {
	return func(l *Log) { l.clock = clock }
}

// Open opens (creating if necessary) the trust log at path for appending.
// The file and its parent directory are created with owner-only
// permissions.
func Open(path string, opts ...Option) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("trust: create %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("trust: open %s: %w", path, err)
	}

	l := &Log{f: f, clock: time.Now}
	for _, opt := range opts {
		opt(l)
	}
	return l, nil
}

// Close closes the underlying file.
func (l *Log) Close() error {
	return l.f.Close()
}

// Add appends an "add" record for e. Add does not check the log's
// cumulative state (that is Load's job): appending a duplicate or
// previously-revoked credential ID succeeds here and surfaces as a Load
// error.
func (l *Log) Add(e Entry) error {
	rec := addRecord{
		Op:           "add",
		CredentialID: base64.RawURLEncoding.EncodeToString(e.CredentialID),
		PublicKey:    base64.StdEncoding.EncodeToString(e.PublicKey),
		Alg:          algString(e.Algorithm),
		RPID:         e.RPID,
		AAGUID:       hex.EncodeToString(e.AAGUID[:]),
		Label:        e.Label,
		At:           l.clock().UTC().Format(time.RFC3339),
	}
	return l.append(rec)
}

// Revoke appends a "revoke" record for credentialID. Like Add, it does not
// check the log's cumulative state: revoking an unknown credential ID
// succeeds here and surfaces as a Load error.
func (l *Log) Revoke(credentialID []byte, reason string) error {
	rec := revokeRecord{
		Op:           "revoke",
		CredentialID: base64.RawURLEncoding.EncodeToString(credentialID),
		Reason:       reason,
		At:           l.clock().UTC().Format(time.RFC3339),
	}
	return l.append(rec)
}

func (l *Log) append(rec any) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("trust: marshal record: %w", err)
	}
	b = append(b, '\n')

	if _, err := l.f.Write(b); err != nil {
		return fmt.Errorf("trust: write record: %w", err)
	}
	return l.f.Sync()
}

// storedKey is a Key plus its current trust state.
type storedKey struct {
	key   Key
	state State
}

// Set is an in-memory snapshot of a trust log, as produced by Load.
type Set struct {
	keys map[string]*storedKey
}

// Lookup reports credentialID's trusted key and trust state. A Key is only
// meaningful when the returned state is StateActive or StateRevoked.
func (s *Set) Lookup(credentialID []byte) (Key, State) {
	sk, ok := s.keys[string(credentialID)]
	if !ok {
		return Key{}, StateUnknown
	}
	return sk.key, sk.state
}

// VerifyAssertion looks up a.CredentialID and, if it is an active trusted
// key, verifies a against it with fido.VerifyAssertion. It returns
// ErrUntrustedKey for an unknown credential, ErrRevokedKey for a revoked
// one, or whatever error fido.VerifyAssertion returns.
func (s *Set) VerifyAssertion(rpID string, a *fido.Assertion, opts fido.VerifyOptions) error {
	key, state := s.Lookup(a.CredentialID)
	switch state {
	case StateRevoked:
		return ErrRevokedKey
	case StateActive:
		return fido.VerifyAssertion(key.PublicKey, key.Algorithm, rpID, a, opts)
	default:
		return ErrUntrustedKey
	}
}

// Load reads and replays the trust log at path, returning the resulting
// Set. A path that does not exist yet loads as an empty, valid Set (a
// fresh trust list before any enrollment). Load returns an error at the
// first record that does not make sense against everything before it:
// invalid JSON, an unknown op, a duplicate add, an add of a
// previously-revoked credential, or a revoke of an unknown or
// already-revoked credential.
func Load(path string) (*Set, error) {
	set := &Set{keys: make(map[string]*storedKey)}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return set, nil
		}
		return nil, fmt.Errorf("trust: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}

		var head opHeader
		if err := json.Unmarshal(line, &head); err != nil {
			return nil, fmt.Errorf("trust: %s:%d: invalid JSON: %w", path, lineNum, err)
		}

		switch head.Op {
		case "add":
			var rec addRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				return nil, fmt.Errorf("trust: %s:%d: invalid add record: %w", path, lineNum, err)
			}
			if err := set.applyAdd(rec); err != nil {
				return nil, fmt.Errorf("trust: %s:%d: %w", path, lineNum, err)
			}
		case "revoke":
			var rec revokeRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				return nil, fmt.Errorf("trust: %s:%d: invalid revoke record: %w", path, lineNum, err)
			}
			if err := set.applyRevoke(rec); err != nil {
				return nil, fmt.Errorf("trust: %s:%d: %w", path, lineNum, err)
			}
		default:
			return nil, fmt.Errorf("trust: %s:%d: unknown op %q", path, lineNum, head.Op)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", path, err)
	}

	return set, nil
}

func (s *Set) applyAdd(rec addRecord) error {
	id, err := base64.RawURLEncoding.DecodeString(rec.CredentialID)
	if err != nil {
		return fmt.Errorf("decode credential_id: %w", err)
	}
	k := string(id)

	if existing, ok := s.keys[k]; ok {
		if existing.state == StateRevoked {
			return fmt.Errorf("credential %s was revoked and cannot be re-added", rec.CredentialID)
		}
		return fmt.Errorf("duplicate add for credential %s", rec.CredentialID)
	}

	pub, err := base64.StdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public_key: %w", err)
	}
	alg, err := algFromString(rec.Alg)
	if err != nil {
		return err
	}
	aaguidBytes, err := hex.DecodeString(rec.AAGUID)
	if err != nil {
		return fmt.Errorf("decode aaguid: %w", err)
	}
	if len(aaguidBytes) != 16 {
		return fmt.Errorf("aaguid must be 16 bytes, got %d", len(aaguidBytes))
	}
	addedAt, err := time.Parse(time.RFC3339, rec.At)
	if err != nil {
		return fmt.Errorf("parse at: %w", err)
	}

	var aaguid [16]byte
	copy(aaguid[:], aaguidBytes)

	s.keys[k] = &storedKey{
		key: Key{
			CredentialID: id,
			PublicKey:    pub,
			Algorithm:    alg,
			RPID:         rec.RPID,
			AAGUID:       aaguid,
			Label:        rec.Label,
			AddedAt:      addedAt,
		},
		state: StateActive,
	}
	return nil
}

func (s *Set) applyRevoke(rec revokeRecord) error {
	id, err := base64.RawURLEncoding.DecodeString(rec.CredentialID)
	if err != nil {
		return fmt.Errorf("decode credential_id: %w", err)
	}
	existing, ok := s.keys[string(id)]
	if !ok {
		return fmt.Errorf("revoke of unknown credential %s", rec.CredentialID)
	}
	if existing.state == StateRevoked {
		return fmt.Errorf("duplicate revoke for credential %s", rec.CredentialID)
	}
	existing.state = StateRevoked
	return nil
}

func algString(alg fido.COSEAlgorithm) string {
	switch alg {
	case fido.ES256:
		return "ES256"
	case fido.EdDSA:
		return "EdDSA"
	default:
		return fmt.Sprintf("%d", int(alg))
	}
}

func algFromString(s string) (fido.COSEAlgorithm, error) {
	switch s {
	case "ES256":
		return fido.ES256, nil
	case "EdDSA":
		return fido.EdDSA, nil
	default:
		return 0, fmt.Errorf("unknown algorithm %q", s)
	}
}
