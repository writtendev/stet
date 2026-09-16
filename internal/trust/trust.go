// Package trust implements stet's local "bring-your-own-key" (BYOK) trust
// list: an append-only JSONL log of hardware public keys a repository (or
// user) has chosen to trust, plus revocations. It is fully offline — the
// log is a local file, and lookups never leave the machine.
//
// Add and Revoke each write one record and fsync, but they are not dumb
// appenders: before writing, each checks the record against the log's
// current cumulative state (tracked in memory, seeded from Load when the
// log is Open'd) and refuses to write anything Load would later reject.
// That keeps an invalid record from ever reaching disk, so one bad
// enrollment or typo'd revoke can't poison every future Load with no
// append-only way to recover. Loading the file (Load) independently
// replays every record in order and is where inconsistency is caught as
// defense in depth: a duplicate add, an add of a previously-revoked
// credential (by credential ID, or by the same underlying public key
// reappearing under a new credential ID), a revoke of an unknown
// credential, or an unrecognized op are all load errors. There is no
// delete or rewrite API; a mistaken add is corrected by revoking it, never
// by editing the file.
//
// Entries do not carry a hardware attestation trust class (e.g. "YubiKey
// series 5" vs "unknown"); that classification is STET-6's decision, made
// from the attestation statement at enrollment time, not stored here.
package trust

import (
	"bufio"
	"crypto/x509"
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
	// set mirrors the log's cumulative on-disk state (seeded from Load at
	// Open time and advanced after each successful append), so Add and
	// Revoke can validate a record before it is written.
	set *Set
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
// permissions. Open also loads the log's existing contents (as Load
// would) to seed the in-memory state Add and Revoke validate against; an
// already-corrupt log fails closed here rather than accepting more writes
// on top of it.
func Open(path string, opts ...Option) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("trust: create %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("trust: open %s: %w", path, err)
	}

	set, err := Load(path)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("trust: load existing log %s: %w", path, err)
	}

	l := &Log{f: f, clock: time.Now, set: set}
	for _, opt := range opts {
		opt(l)
	}
	return l, nil
}

// Close closes the underlying file.
func (l *Log) Close() error {
	return l.f.Close()
}

// Add appends an "add" record for e. Before writing, Add checks e against
// the log's current cumulative state (the same checks Load applies) and
// refuses to write a record that state would reject — a duplicate
// credential ID, a credential ID or public key that was previously
// revoked, an unrecognized algorithm, an unparseable public key, or an
// empty credential ID. That way an invalid record never reaches disk.
func (l *Log) Add(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

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

	if _, _, err := l.set.checkAdd(rec); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	if err := l.appendLocked(rec); err != nil {
		return err
	}
	// checkAdd already validated rec against l.set above, so this cannot
	// fail; applyAdd just commits the same result to the in-memory state.
	return l.set.applyAdd(rec)
}

// Revoke appends a "revoke" record for credentialID. Like Add, it checks
// the log's current cumulative state first and refuses to write a revoke
// of an unknown or already-revoked credential ID, so an invalid record
// never reaches disk.
func (l *Log) Revoke(credentialID []byte, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	rec := revokeRecord{
		Op:           "revoke",
		CredentialID: base64.RawURLEncoding.EncodeToString(credentialID),
		Reason:       reason,
		At:           l.clock().UTC().Format(time.RFC3339),
	}

	if _, err := l.set.checkRevoke(rec); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	if err := l.appendLocked(rec); err != nil {
		return err
	}
	return l.set.applyRevoke(rec)
}

// appendLocked marshals and writes rec, fsyncing before it returns. Callers
// must hold l.mu.
func (l *Log) appendLocked(rec any) error {
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
	// byPubKey indexes the same storedKey values by their canonical PKIX
	// DER public key bytes, so an add can be checked against every
	// previously-seen key regardless of which credential ID it was filed
	// under.
	byPubKey map[string]*storedKey
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
	set := &Set{keys: make(map[string]*storedKey), byPubKey: make(map[string]*storedKey)}

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

// applyAdd validates rec against s (see checkAdd) and, on success, commits
// it: the new key is indexed both by credential ID and by its canonical
// public key.
func (s *Set) applyAdd(rec addRecord) error {
	key, canon, err := s.checkAdd(rec)
	if err != nil {
		return err
	}
	sk := &storedKey{key: key, state: StateActive}
	s.keys[string(key.CredentialID)] = sk
	s.byPubKey[canon] = sk
	return nil
}

// checkAdd validates rec against s's current state without mutating s. On
// success it returns the decoded Key and the canonical PKIX DER form of
// its public key (as used to index Set.byPubKey); on failure the returned
// values are meaningless.
//
// Checks, in order: the credential ID decodes and is non-empty and not
// already active or revoked; the public key decodes, parses as a valid
// PKIX public key, and does not match any key already active or revoked
// under a different credential ID (revocation binds to the key, not just
// the ID it was filed under); the algorithm is one this package
// recognizes; the AAGUID is exactly 16 bytes; and the timestamp parses.
func (s *Set) checkAdd(rec addRecord) (Key, string, error) {
	id, err := base64.RawURLEncoding.DecodeString(rec.CredentialID)
	if err != nil {
		return Key{}, "", fmt.Errorf("decode credential_id: %w", err)
	}
	if len(id) == 0 {
		return Key{}, "", fmt.Errorf("credential_id must not be empty")
	}

	if existing, ok := s.keys[string(id)]; ok {
		if existing.state == StateRevoked {
			return Key{}, "", fmt.Errorf("credential %s was revoked and cannot be re-added", rec.CredentialID)
		}
		return Key{}, "", fmt.Errorf("duplicate add for credential %s", rec.CredentialID)
	}

	pub, err := base64.StdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return Key{}, "", fmt.Errorf("decode public_key: %w", err)
	}
	canon, err := canonicalPublicKey(pub)
	if err != nil {
		return Key{}, "", err
	}
	if existing, ok := s.byPubKey[canon]; ok {
		existingID := base64.RawURLEncoding.EncodeToString(existing.key.CredentialID)
		if existing.state == StateRevoked {
			return Key{}, "", fmt.Errorf("public key matches revoked credential %s and cannot be re-added under credential %s", existingID, rec.CredentialID)
		}
		return Key{}, "", fmt.Errorf("public key already trusted under credential %s, cannot add again under credential %s", existingID, rec.CredentialID)
	}

	alg, err := algFromString(rec.Alg)
	if err != nil {
		return Key{}, "", err
	}
	aaguidBytes, err := hex.DecodeString(rec.AAGUID)
	if err != nil {
		return Key{}, "", fmt.Errorf("decode aaguid: %w", err)
	}
	if len(aaguidBytes) != 16 {
		return Key{}, "", fmt.Errorf("aaguid must be 16 bytes, got %d", len(aaguidBytes))
	}
	addedAt, err := time.Parse(time.RFC3339, rec.At)
	if err != nil {
		return Key{}, "", fmt.Errorf("parse at: %w", err)
	}

	var aaguid [16]byte
	copy(aaguid[:], aaguidBytes)

	return Key{
		CredentialID: id,
		PublicKey:    []byte(canon),
		Algorithm:    alg,
		RPID:         rec.RPID,
		AAGUID:       aaguid,
		Label:        rec.Label,
		AddedAt:      addedAt,
	}, canon, nil
}

// applyRevoke validates rec against s (see checkRevoke) and, on success,
// flips the matching entry's state to StateRevoked.
func (s *Set) applyRevoke(rec revokeRecord) error {
	sk, err := s.checkRevoke(rec)
	if err != nil {
		return err
	}
	sk.state = StateRevoked
	return nil
}

// checkRevoke validates rec against s's current state without mutating s,
// returning the matching storedKey on success: the credential ID decodes
// and is currently known and not already revoked.
func (s *Set) checkRevoke(rec revokeRecord) (*storedKey, error) {
	id, err := base64.RawURLEncoding.DecodeString(rec.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("decode credential_id: %w", err)
	}
	existing, ok := s.keys[string(id)]
	if !ok {
		return nil, fmt.Errorf("revoke of unknown credential %s", rec.CredentialID)
	}
	if existing.state == StateRevoked {
		return nil, fmt.Errorf("duplicate revoke for credential %s", rec.CredentialID)
	}
	return existing, nil
}

// canonicalPublicKey parses der as a PKIX public key and re-marshals it,
// returning the canonical encoding as a string suitable for use as a map
// key. Re-marshaling normalizes any DER encoding variations (e.g.
// non-minimal integer encodings) that would otherwise let the same key
// evade the byPubKey index under a byte-for-byte different encoding.
func canonicalPublicKey(der []byte) (string, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", fmt.Errorf("parse public_key: %w", err)
	}
	canon, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public_key: %w", err)
	}
	return string(canon), nil
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
