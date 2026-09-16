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
// errors.
//
// The commit rule for the file's final line, which is the only line that
// can legitimately lack a trailing newline, is: a record is committed iff
// its line parses as complete, valid JSON. A write that is cut short
// part-way through a record (e.g. ENOSPC) can never produce valid JSON —
// the closing brace is the last byte written — so that shape is an
// uncommitted, not-yet-written fragment, and Load silently drops it
// rather than failing the whole log. A final line that does parse,
// despite lacking its newline, is already a complete record — for
// example one hand-appended with `printf`/`echo -n`, or written by
// something outside this package — and Load replays it exactly like any
// other line, including rejecting it if it fails the usual per-op or
// semantic checks.
//
// Add and Revoke apply the same rule before appending, and additionally
// repair the file so the next write always lands after a clean,
// newline-terminated boundary: an unterminated line that parses gets its
// missing '\n' appended (an addition, never touching an existing byte);
// an unterminated fragment that does not parse gets truncated away back
// to the offset where it begins (removing only bytes that were never
// part of a committed record). If a write itself then fails partway
// through, what happens to the bytes it landed follows the same commit
// rule, not the byte count the failed Write call reported: if what
// landed (with, at most, its trailing '\n' missing) already parses as a
// complete record, it is completed with the missing terminator and the
// call reports success, because a concurrent Load could already observe
// it as committed; only a landed prefix that does not parse -- a
// genuine fragment -- is truncated back to the file's size from just
// before that write. None of this is a rewrite: every byte removed by a
// truncation was, by the commit rule above, never part of a committed
// record in the first place, and every byte added is a terminator for a
// record that was already committed. No committed record is ever
// removed or rewritten -- that is what "append-only" means here. There
// is still no delete or rewrite API for a committed record; a mistaken
// add is corrected by revoking it, never by editing the file.
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
// Load's commit rule for a final, newline-less line (see the package
// doc). Unlike Load, which only reads, reloadLocked also repairs the
// on-disk file so the append that follows always lands after a clean,
// newline-terminated boundary:
//
//   - a final line that parses (already committed, just missing its
//     terminator) gets a single '\n' appended to the file — an addition
//     that touches no existing byte;
//   - a final line that does not parse (an uncommitted fragment) gets
//     the file truncated back to the offset right after the last
//     complete record, discarding only bytes that were never part of a
//     committed record.
//
// Either repair keeps append-only intact: nothing committed is ever
// removed or rewritten. Callers must hold l.mu and the flock (see
// lockFile).
func (l *Log) reloadLocked() (*Set, error) {
	if _, err := l.f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("trust: seek %s: %w", l.path, err)
	}
	data, err := io.ReadAll(l.f)
	if err != nil {
		return nil, fmt.Errorf("trust: read %s: %w", l.path, err)
	}

	if len(data) > 0 && data[len(data)-1] != '\n' {
		i := bytes.LastIndexByte(data, '\n')
		tail := data[i+1:]
		if json.Valid(tail) {
			// Already a committed record by the commit rule; it is
			// only missing its terminator. Supply it.
			if err := l.terminateLocked(); err != nil {
				return nil, err
			}
			data = append(data, '\n')
		} else {
			// An uncommitted fragment. Discard exactly the bytes after
			// the last completed record; nothing before that offset is
			// touched.
			truncateAt := int64(i + 1)
			if err := l.truncateLocked(truncateAt); err != nil {
				return nil, err
			}
			data = data[:truncateAt]
		}
	}

	return loadRecords(data, l.path)
}

// terminateLocked appends a single '\n' at the current end of the file
// and fsyncs. Callers must hold l.mu and the flock, and must only call
// this when reloadLocked has determined the raw tail is already a
// complete, valid record that is simply missing its terminator — this
// never rewrites or removes a byte, it only supplies the terminator a
// committed record was always missing.
func (l *Log) terminateLocked() error {
	if _, err := l.f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("trust: seek %s: %w", l.path, err)
	}
	if _, err := l.f.Write([]byte("\n")); err != nil {
		return fmt.Errorf("trust: terminate %s: %w", l.path, err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("trust: sync %s: %w", l.path, err)
	}
	return nil
}

// truncateLocked truncates the file to size and fsyncs. Callers must
// hold l.mu and the flock, and must only pass a size that removes
// nothing but bytes reloadLocked has determined were never part of a
// committed record (an uncommitted trailing fragment, or — from
// appendLocked — the tail of a write that itself just failed
// partway through). Append-only means no committed record is ever
// removed or rewritten by this call.
func (l *Log) truncateLocked(size int64) error {
	if err := l.f.Truncate(size); err != nil {
		return fmt.Errorf("trust: truncate %s: %w", l.path, err)
	}
	if _, err := l.f.Seek(size, io.SeekStart); err != nil {
		return fmt.Errorf("trust: seek %s: %w", l.path, err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("trust: sync %s: %w", l.path, err)
	}
	return nil
}

// appendLocked marshals and writes rec, fsyncing before it returns. If
// the write itself fails partway through, what happens to the bytes it
// did land depends on whether they already form a committed record by
// the commit rule (see the package doc): a write that lands everything
// except (at most) the trailing '\n' has already produced a complete,
// parseable record -- indistinguishable from a hand-appended record
// missing its terminator, which Load and reloadLocked both already
// treat as committed. Truncating that away would delete a record a
// concurrent Load could already have observed (e.g. a revoke, silently
// reverting a key from revoked back to active). So appendLocked inspects
// what actually landed on disk, not the byte count Write reported:
//
//   - if it parses as a complete record, the record is committed; the
//     missing terminator (if any) is supplied and fsynced, and this
//     reports success (nil) rather than the write error, so a caller
//     never sees an error for a record that is, in fact, on disk and
//     loadable;
//   - otherwise it is an uncommitted fragment, and the file is
//     truncated back to the size it had immediately before this call,
//     undoing only bytes that were never part of a committed record
//     (the caller never saw this call succeed on that fragment).
//
// Callers must hold l.mu and the flock, and must have just called
// reloadLocked so the file's tail is a clean boundary to append onto.
func (l *Log) appendLocked(rec any) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("trust: marshal record: %w", err)
	}
	b = append(b, '\n')

	preWriteSize, err := l.f.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("trust: seek %s: %w", l.path, err)
	}

	if _, werr := l.w.Write(b); werr != nil {
		return l.recoverFailedWriteLocked(preWriteSize, werr)
	}
	if err := l.w.Sync(); err != nil {
		return fmt.Errorf("trust: sync record: %w", err)
	}
	return nil
}

// recoverFailedWriteLocked is called after appendLocked's Write reports
// an error. It reads back whatever actually landed on disk after
// preWriteSize (the file's size immediately before that Write) -- not
// the byte count Write returned -- since only bytes actually on disk can
// be observed by a concurrent Load.
//
// If that tail, with at most a missing trailing '\n', already parses as
// a complete record, the commit rule (see the package doc) already
// counts it as committed: this supplies the missing terminator and
// fsyncs, then returns nil, reporting the append as successful rather
// than surfacing writeErr for a record that is in fact on disk. If the
// tail does not parse, it is an uncommitted fragment: this truncates the
// file back to preWriteSize and returns writeErr. Callers must hold l.mu
// and the flock.
func (l *Log) recoverFailedWriteLocked(preWriteSize int64, writeErr error) error {
	if _, err := l.f.Seek(preWriteSize, io.SeekStart); err != nil {
		return fmt.Errorf("trust: write record: %w (additionally failed to inspect the partial write: %v)", writeErr, err)
	}
	tail, err := io.ReadAll(l.f)
	if err != nil {
		return fmt.Errorf("trust: write record: %w (additionally failed to inspect the partial write: %v)", writeErr, err)
	}

	if trimmed := bytes.TrimSuffix(tail, []byte("\n")); len(trimmed) > 0 && json.Valid(trimmed) {
		// Everything but, at most, the trailing newline landed: already
		// a committed record by the commit rule. Complete it rather
		// than discarding it.
		if !bytes.HasSuffix(tail, []byte("\n")) {
			if err := l.terminateLocked(); err != nil {
				return fmt.Errorf("trust: write record: %w (record landed on disk but failed to terminate it: %v)", writeErr, err)
			}
		}
		return nil
	}

	if terr := l.truncateLocked(preWriteSize); terr != nil {
		return fmt.Errorf("trust: write record: %w (additionally failed to undo the partial write: %v)", writeErr, terr)
	}
	return fmt.Errorf("trust: write record: %w", writeErr)
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
// first committed record that does not make sense against everything
// before it: invalid JSON, an unknown op, a duplicate add, an add of a
// previously-revoked credential, or a revoke of an unknown or
// already-revoked credential.
//
// The file's final line is the only one allowed to lack a trailing
// newline, and whether it counts as committed follows one rule: it is
// committed iff it parses as complete, valid JSON. A write cut short
// part-way through a record (for example, ENOSPC) can never satisfy
// that — the closing brace is the last byte written — so that shape is
// an uncommitted fragment, and Load silently drops it rather than
// failing the whole log over it. A final line that does parse is
// already a complete record despite the missing newline (e.g. hand
// appended, or written by something else), and Load replays it exactly
// like any other line, including erroring on it if it fails the checks
// above.
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
// If data does not end in a newline, its final line is judged by the
// commit rule: dropped, silently, if it does not parse as complete,
// valid JSON (an uncommitted fragment — see Load's doc); kept and
// replayed exactly like any other line if it does parse (a committed
// record that is simply missing its terminator). Every other,
// newline-terminated line is always replayed strictly.
func loadRecords(data []byte, path string) (*Set, error) {
	set := &Set{keys: make(map[string]*storedKey), byPubKey: make(map[string]*storedKey)}

	if len(data) > 0 && data[len(data)-1] != '\n' {
		i := bytes.LastIndexByte(data, '\n')
		tail := data[i+1:]
		if !json.Valid(tail) {
			if i >= 0 {
				data = data[:i+1]
			} else {
				// The entire file is one unterminated fragment:
				// nothing in it has ever been committed.
				data = nil
			}
		}
		// else: tail is complete, valid JSON despite the missing
		// newline. Leave data as-is; bytes.Split below still yields it
		// as the final "line" and the loop replays it normally.
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
