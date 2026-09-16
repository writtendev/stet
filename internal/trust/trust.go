// Package trust implements stet's local "bring-your-own-key" (BYOK) trust
// list: an append-only JSONL log of hardware public keys a repository (or
// user) has chosen to trust, plus revocations. It is fully offline — the
// log is a local file, and lookups never leave the machine.
//
// Add and Revoke each write one record and fsync, but they are not dumb
// appenders: before writing, each takes an exclusive advisory lock
// (flock) on the file, re-reads and replays the file's *current* on-disk
// contents from scratch (never a cached copy), and checks the record
// against that fresh state before appending — the same checks Load
// applies. Locking plus a fresh reload on every call is what keeps an
// invalid record from ever reaching disk even when one Log handle's view
// of the file could otherwise be stale:
//
//   - a Sync that fails after the Write it followed already landed on
//     disk (the caller sees an error and naturally retries the same
//     Add/Revoke; the retry's fresh reload sees the record that's
//     already there and refuses the duplicate instead of writing it
//     again);
//   - two Log handles open on the same path, in this process or two
//     separate processes, one of which predates a write the other made
//     (the flock serializes them, and each reload picks up what the
//     other wrote).
//
// Loading the file (Load) independently replays every record in order
// and is where inconsistency is caught as defense in depth: a duplicate
// add, an add of a previously-revoked credential (by credential ID, or by
// the same underlying public key reappearing under a new credential ID),
// a revoke of an unknown credential, or an unrecognized op are all load
// errors. The one exception is a final line with no trailing newline: a
// write that was cut short part-way through a record (e.g. ENOSPC) leaves
// exactly that shape, so Load treats it as not-yet-committed and drops it
// rather than failing the whole log. Add and Revoke, however, refuse to
// write anything more once they see that shape, rather than silently
// gluing a new record onto the dangling fragment — doing that would turn
// a harmless, ignorable tail into a permanently unparseable line. There
// is no delete or rewrite API, including for that dangling fragment; a
// mistaken add is corrected by revoking it, never by editing the file.
//
// Entries do not carry a hardware attestation trust class (e.g. "YubiKey
// series 5" vs "unknown"); that classification is STET-6's decision, made
// from the attestation statement at enrollment time, not stored here.
package trust

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
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

// syncer is the subset of *os.File that appendLocked needs to commit a
// record: write its bytes, then fsync. It exists so tests can substitute
// a fake that fails Sync (or Write) on demand, to exercise the
// write-succeeds-but-sync-fails recovery path without needing real disk
// pressure or I/O errors.
type syncer interface {
	Write([]byte) (int, error)
	Sync() error
}

// Log is an append-only writer for the trust log file.
type Log struct {
	// mu serializes Add/Revoke calls against this one Log handle (e.g.
	// from concurrent goroutines in this process). It does not, by
	// itself, serialize against a different Log handle open on the same
	// path — that is flock's job, taken fresh inside each Add/Revoke.
	mu    sync.Mutex
	path  string
	f     *os.File
	w     syncer
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
// permissions. Open also loads the log's existing contents (as Load
// would): an already-corrupt log fails closed here rather than accepting
// more writes on top of it. That initial load is only a fail-fast check,
// though — Add and Revoke never trust it, or any other cached view of the
// file; each re-reads the file from scratch under an exclusive lock
// before validating and writing.
func Open(path string, opts ...Option) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("trust: create %s: %w", filepath.Dir(path), err)
	}
	// O_RDWR (not O_WRONLY): Add/Revoke read the file back under the
	// flock, via this same handle, to reload its current contents before
	// validating and appending.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("trust: open %s: %w", path, err)
	}

	if _, err := Load(path); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("trust: load existing log %s: %w", path, err)
	}

	l := &Log{path: path, f: f, w: f, clock: time.Now}
	for _, opt := range opts {
		opt(l)
	}
	return l, nil
}

// Close closes the underlying file.
func (l *Log) Close() error {
	return l.f.Close()
}

// Add appends an "add" record for e. Add takes an exclusive lock on the
// file, re-reads and replays its current on-disk contents, and checks e
// against that fresh state (the same checks Load applies) before
// writing — a duplicate credential ID, a credential ID or public key
// that was previously revoked, an unrecognized algorithm, an unparseable
// public key, or an empty credential ID are all refused. That way an
// invalid record never reaches disk, and the check can't go stale
// relative to a write this or another Log handle already made.
func (l *Log) Add(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	unlock, err := l.lockFile()
	if err != nil {
		return err
	}
	defer unlock()

	set, err := l.reloadLocked()
	if err != nil {
		return err
	}

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

	if _, _, err := set.checkAdd(rec); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	return l.appendLocked(rec)
}

// Revoke appends a "revoke" record for credentialID. Like Add, it takes
// an exclusive lock, re-reads the file's current contents, and refuses a
// revoke of an unknown or already-revoked credential ID against that
// fresh state, so an invalid record never reaches disk.
func (l *Log) Revoke(credentialID []byte, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	unlock, err := l.lockFile()
	if err != nil {
		return err
	}
	defer unlock()

	set, err := l.reloadLocked()
	if err != nil {
		return err
	}

	rec := revokeRecord{
		Op:           "revoke",
		CredentialID: base64.RawURLEncoding.EncodeToString(credentialID),
		Reason:       reason,
		At:           l.clock().UTC().Format(time.RFC3339),
	}

	if _, err := set.checkRevoke(rec); err != nil {
		return fmt.Errorf("trust: %w", err)
	}
	return l.appendLocked(rec)
}

// lockFile takes an exclusive advisory lock (flock) on the log file, so
// that "reload current state, validate, append, fsync" runs as one
// atomic-enough unit against any other Log handle on the same path —
// whether that handle lives in this process or another. It returns a
// function that releases the lock; callers must hold l.mu and call the
// returned function before returning.
func (l *Log) lockFile() (func(), error) {
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("trust: lock %s: %w", l.path, err)
	}
	return func() {
		_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	}, nil
}

// reloadLocked re-reads the log file from scratch (never a cached view)
// and replays it into a fresh Set, the same way Load does — including
// Load's tolerance of a final, newline-less line as a not-yet-committed
// write that was cut short. It additionally refuses to proceed at all
// when the file's raw tail is in that shape: Add/Revoke must not append
// anything while a dangling, uncommitted fragment sits at the end, since
// doing so would glue the new record onto it and turn a harmless,
// ignorable fragment into a permanently unparseable line. Callers must
// hold l.mu and the flock (see lockFile).
func (l *Log) reloadLocked() (*Set, error) {
	if _, err := l.f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("trust: seek %s: %w", l.path, err)
	}
	data, err := io.ReadAll(l.f)
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", l.path, err)
	}

	if len(data) > 0 && data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("trust: %s ends in an unterminated record (a previous write was likely cut short); refusing to append until it is resolved", l.path)
	}

	return loadRecords(data, l.path)
}

// appendLocked marshals and writes rec, fsyncing before it returns.
// Callers must hold l.mu and the flock (see lockFile).
func (l *Log) appendLocked(rec any) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("trust: marshal record: %w", err)
	}
	b = append(b, '\n')

	if _, err := l.w.Write(b); err != nil {
		return fmt.Errorf("trust: write record: %w", err)
	}
	if err := l.w.Sync(); err != nil {
		return fmt.Errorf("trust: sync record: %w", err)
	}
	return nil
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
// first complete (newline-terminated) record that does not make sense
// against everything before it: invalid JSON, an unknown op, a duplicate
// add, an add of a previously-revoked credential, or a revoke of an
// unknown or already-revoked credential.
//
// A final line with no trailing newline is the exception: it is the
// shape a write leaves when it is cut short part-way through a record
// (for example, ENOSPC), so Load treats it as not-yet-committed and
// silently drops it rather than failing the whole log over it.
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Set{keys: make(map[string]*storedKey), byPubKey: make(map[string]*storedKey)}, nil
		}
		return nil, fmt.Errorf("trust: open %s: %w", path, err)
	}
	return loadRecords(data, path)
}

// loadRecords replays the JSONL content in data, as read from the trust
// log at path (path is used only in error messages), returning the
// resulting Set.
//
// If data does not end in a newline, its final, unterminated line is
// dropped before replay: that shape means the write that produced it was
// cut short, so the line is treated as not-yet-committed rather than as
// corruption. Every remaining, newline-terminated line is still replayed
// strictly.
func loadRecords(data []byte, path string) (*Set, error) {
	set := &Set{keys: make(map[string]*storedKey), byPubKey: make(map[string]*storedKey)}

	if len(data) > 0 && data[len(data)-1] != '\n' {
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i+1]
		} else {
			// The entire file is one unterminated line: nothing in it
			// has ever been committed.
			data = nil
		}
	}

	lineNum := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		lineNum++
		if len(bytes.TrimSpace(line)) == 0 {
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
