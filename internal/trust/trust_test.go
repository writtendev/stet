package trust

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/writtendev/stet/internal/fido"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// testPublicKey deterministically derives a distinct, validly-encoded
// PKIX ECDSA P-256 public key for label: the same label always yields the
// same key (needed by TestAddIsDeterministicUnderFixedClock), and
// different labels yield different keys (so tests that add several
// entries to one log don't collide on the new by-public-key check).
//
// It computes the key directly (private scalar = SHA-256(label) mod N)
// rather than via ecdsa.GenerateKey: that function deliberately consumes
// a non-deterministic amount of entropy from its rand.Reader
// (crypto/internal/randutil's "maybe read one extra byte" guard against
// exactly this kind of fixed-seed reuse), so it cannot be made to
// reproduce the same key twice.
func testPublicKey(t *testing.T, label string) []byte {
	t.Helper()
	seed := sha256.Sum256([]byte("trust-test-key-" + label))

	d := new(big.Int).SetBytes(seed[:])
	d.Mod(d, elliptic.P256().Params().N)
	if d.Sign() == 0 {
		d.SetInt64(1)
	}
	scalar := make([]byte, 32)
	d.FillBytes(scalar)

	priv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der
}

// rawTestPublicKeyBase64 returns testPublicKey(t, label) as the
// base64.StdEncoding string a hand-written on-disk "add" record's
// public_key field expects.
func rawTestPublicKeyBase64(t *testing.T, label string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(testPublicKey(t, label))
}

func testEntry(t *testing.T, label string) Entry {
	t.Helper()
	return Entry{
		CredentialID: []byte("cred-" + label),
		PublicKey:    testPublicKey(t, label),
		Algorithm:    fido.ES256,
		RPID:         fido.DefaultRPID,
		AAGUID:       [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Label:        label,
	}
}

func TestAddReloadLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entry := testEntry(t, "alice")
	if err := log.Add(entry); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	key, state := set.Lookup(entry.CredentialID)
	if state != StateActive {
		t.Fatalf("state = %v, want StateActive", state)
	}
	if string(key.PublicKey) != string(entry.PublicKey) {
		t.Errorf("PublicKey = %q, want %q", key.PublicKey, entry.PublicKey)
	}
	if key.RPID != entry.RPID || key.Algorithm != entry.Algorithm || key.AAGUID != entry.AAGUID || key.Label != entry.Label {
		t.Errorf("round-tripped key does not match: %+v", key)
	}
	if !key.AddedAt.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("AddedAt = %v, want the fixed clock value", key.AddedAt)
	}

	if _, state := set.Lookup([]byte("never-added")); state != StateUnknown {
		t.Errorf("state for unknown credential = %v, want StateUnknown", state)
	}
}

func TestRevokeThenLookupAndReAddFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	entry := testEntry(t, "bob")
	if err := log.Add(entry); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := log.Revoke(entry.CredentialID, "lost device"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, state := set.Lookup(entry.CredentialID); state != StateRevoked {
		t.Fatalf("state = %v, want StateRevoked", state)
	}

	// Re-adding a revoked credential must be refused by Add itself: the
	// log's in-memory state already knows the credential is revoked, so
	// the invalid record never reaches disk, and the log stays loadable.
	if err := log.Add(entry); err == nil {
		t.Fatalf("Add (re-add of revoked credential): expected an error")
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load after a refused re-add: %v, want the log to remain valid", err)
	}
}

// TestReAddRevokedKeyUnderNewCredentialIDFails covers the round-1 review
// finding: revocation must bind to the public key, not just the
// credential ID label it was filed under. Re-adding the same key under a
// brand new credential ID must be refused too.
func TestReAddRevokedKeyUnderNewCredentialIDFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	entry := testEntry(t, "gina")
	if err := log.Add(entry); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := log.Revoke(entry.CredentialID, "lost device"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	reAdd := entry
	reAdd.CredentialID = []byte("cred-gina-new-id")
	if err := log.Add(reAdd); err == nil {
		t.Fatalf("Add (same key, new credential ID, after revoke): expected an error")
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, state := set.Lookup(reAdd.CredentialID); state != StateUnknown {
		t.Errorf("state for the rejected re-add's new ID = %v, want StateUnknown", state)
	}
}

// TestDuplicateAddIsRefused documents the tightened contract: Add now
// checks the log's own current state before writing, so a duplicate add
// is refused immediately by Add and never reaches disk. Load's own
// duplicate-add rejection (defense in depth for a log written by
// something other than this package, or hand-edited) is covered by
// TestUnknownOpIsLoadError and friends via a raw on-disk record.
func TestDuplicateAddIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	entry := testEntry(t, "carol")
	if err := log.Add(entry); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := log.Add(entry); err == nil {
		t.Fatalf("Add (duplicate): expected an error")
	}

	if _, err := Load(path); err != nil {
		t.Fatalf("Load after a refused duplicate add: %v, want the log to remain valid", err)
	}
}

// TestDuplicateAddRecordOnDiskIsLoadError covers Load's defense-in-depth
// check directly, bypassing Add/Revoke's own validation by writing the
// records to disk by hand (as a log written by another tool, or corrupted
// some other way, might contain).
func TestDuplicateAddRecordOnDiskIsLoadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")
	rec := `{"op":"add","credential_id":"aGVsbG8","public_key":"` +
		rawTestPublicKeyBase64(t, "duplicate-on-disk") +
		`","alg":"ES256","rp_id":"stet","aaguid":"0102030405060708090a0b0c0d0e0f10","label":"x","at":"2026-01-02T03:04:05Z"}` + "\n"
	if err := os.WriteFile(path, []byte(rec+rec), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("Load with a duplicate add record on disk: expected an error")
	}
}

// TestRevokeUnknownCredentialIsRefused mirrors
// TestDuplicateAddIsRefused for Revoke: revoking a credential ID the log
// has never seen is refused immediately and never reaches disk.
func TestRevokeUnknownCredentialIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	if err := log.Revoke([]byte("nobody"), "n/a"); err == nil {
		t.Fatalf("Revoke (unknown credential): expected an error")
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load after a refused revoke: %v, want the log to remain valid", err)
	}
}

// TestRevokeUnknownCredentialRecordOnDiskIsLoadError is Load's
// defense-in-depth counterpart to TestRevokeUnknownCredentialIsRefused,
// for a hand-written record that never went through Revoke.
func TestRevokeUnknownCredentialRecordOnDiskIsLoadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")
	rec := `{"op":"revoke","credential_id":"bm9ib2R5","reason":"n/a","at":"2026-01-02T03:04:05Z"}` + "\n"
	if err := os.WriteFile(path, []byte(rec), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("Load with a revoke of an unknown credential: expected an error")
	}
}

func TestUnknownOpIsLoadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")
	if err := os.WriteFile(path, []byte(`{"op":"delete","credential_id":"x"}`+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("Load with an unknown op: expected an error")
	}
}

func TestLoadMissingFileIsEmptySet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.jsonl")
	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, state := set.Lookup([]byte("anything")); state != StateUnknown {
		t.Errorf("state = %v, want StateUnknown", state)
	}
}

func TestFileOnlyGrowsAcrossAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	if err := log.Add(testEntry(t, "dave")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if err := log.Add(testEntry(t, "erin")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if len(second) <= len(first) {
		t.Fatalf("file did not grow: %d bytes then %d bytes", len(first), len(second))
	}
	if !strings.HasPrefix(string(second), string(first)) {
		t.Fatalf("earlier content is not a byte prefix of the file after a new append")
	}
}

func TestAddIsDeterministicUnderFixedClock(t *testing.T) {
	at := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	path1 := filepath.Join(t.TempDir(), "a.jsonl")
	log1, err := Open(path1, WithClock(fixedClock(at)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := log1.Add(testEntry(t, "frank")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	_ = log1.Close()

	path2 := filepath.Join(t.TempDir(), "b.jsonl")
	log2, err := Open(path2, WithClock(fixedClock(at)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := log2.Add(testEntry(t, "frank")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	_ = log2.Close()

	b1, err := os.ReadFile(path1)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	b2, err := os.ReadFile(path2)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("output differs under an identical fixed clock:\n%s\nvs\n%s", b1, b2)
	}
}

func TestOpenCreatesOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "trusted-keys.jsonl")
	log, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %v, want 0600", perm)
	}
}

func TestDefaultPath(t *testing.T) {
	path, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("stet", "trusted-keys.jsonl")) {
		t.Errorf("DefaultPath = %q, want a path ending in stet/trusted-keys.jsonl", path)
	}
}

// The tests below cover the round-2 review finding: Add/Revoke used to
// validate a new record only against an in-memory Set seeded once at
// Open, with no locking and no reload, so that state could diverge from
// the file on disk (a Sync failure followed by a caller retry, a short
// write leaving a torn trailing line, or a second writer on the same
// path) and let through a record Load would later reject, poisoning the
// log for good. The fix: Add/Revoke now take an exclusive flock and
// re-read the file from scratch before validating, and Load tolerates a
// final line with no trailing newline as not-yet-committed instead of
// failing the whole log over it.

// flakySync wraps an *os.File and can be made to fail its next Sync call
// exactly once, to simulate a write that reached disk but whose fsync
// failed -- without needing real disk pressure or injected I/O errors.
type flakySync struct {
	*os.File
	failSyncOnce bool
}

func (w *flakySync) Sync() error {
	if w.failSyncOnce {
		w.failSyncOnce = false
		return errors.New("simulated fsync failure")
	}
	return w.File.Sync()
}

// TestAddSurvivesSyncFailureOnRetry covers scenario 1 from the finding: a
// Write succeeds (the record's bytes, including its trailing newline,
// are on disk) but the following Sync fails, so Add returns an error and
// the caller retries the same Add. A retry that trusted stale in-memory
// state would append the identical record a second time and leave the
// log permanently unloadable ("duplicate add" at every future Load).
// Add must instead reload from disk before checking, see the record
// that's already there, and refuse the retry as a duplicate.
func TestAddSurvivesSyncFailureOnRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	entry := testEntry(t, "irene")
	log.w = &flakySync{File: log.f, failSyncOnce: true}

	if err := log.Add(entry); err == nil {
		t.Fatalf("Add: expected the simulated sync failure to surface")
	}

	if err := log.Add(entry); err == nil {
		t.Fatalf("Add (retry after a sync failure): expected a duplicate error, not success")
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load after the retried Add: %v, want the log to remain valid", err)
	}
	if _, state := set.Lookup(entry.CredentialID); state != StateActive {
		t.Errorf("state = %v, want StateActive (the record was written exactly once)", state)
	}
}

// TestSecondLogHandleSeesFirstsWrites covers scenario 3 from the finding
// (two writers on the same path): log2 is Open'd, and only afterward does
// log1 add a credential. log2's initial seed therefore predates that
// write -- but Add must reload the file fresh each time, so log2 still
// refuses to re-add the same credential rather than writing a duplicate
// that would make the log unloadable.
func TestSecondLogHandleSeesFirstsWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log1, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open (log1): %v", err)
	}
	defer func() { _ = log1.Close() }()

	log2, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open (log2): %v", err)
	}
	defer func() { _ = log2.Close() }()

	entry := testEntry(t, "hank")
	if err := log1.Add(entry); err != nil {
		t.Fatalf("log1.Add: %v", err)
	}

	if err := log2.Add(entry); err == nil {
		t.Fatalf("log2.Add (already added by log1): expected a duplicate error")
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, state := set.Lookup(entry.CredentialID); state != StateActive {
		t.Errorf("state = %v, want StateActive", state)
	}
}

// TestConcurrentLogsSerializeAndStayConsistent opens many Log handles on
// the same path and adds a distinct credential from each concurrently.
// Each Log handle has its own *os.File (its own open file description),
// so this exercises the same flock-based serialization two separate
// processes on the same path would rely on. Every add must succeed and
// the log must stay loadable, with every credential present exactly
// once.
func TestConcurrentLogsSerializeAndStayConsistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			label := fmt.Sprintf("writer-%d", i)
			log, err := Open(path, WithClock(fixedClock(time.Now())))
			if err != nil {
				errs <- fmt.Errorf("Open (%s): %w", label, err)
				return
			}
			defer func() { _ = log.Close() }()
			if err := log.Add(testEntry(t, label)); err != nil {
				errs <- fmt.Errorf("Add (%s): %w", label, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Add failed: %v", err)
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load after concurrent adds: %v", err)
	}
	for i := 0; i < n; i++ {
		id := []byte("cred-" + fmt.Sprintf("writer-%d", i))
		if _, state := set.Lookup(id); state != StateActive {
			t.Errorf("writer-%d: state = %v, want StateActive", i, state)
		}
	}
}

// TestLoadIgnoresUnterminatedTrailingLine covers scenario 2 from the
// finding: a write that is cut short leaves a final line with no
// trailing newline. Load must tolerate exactly that shape -- treating it
// as not-yet-committed rather than corruption -- while still returning
// everything that was cleanly committed before it.
func TestLoadIgnoresUnterminatedTrailingLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	good := `{"op":"add","credential_id":"aGVsbG8","public_key":"` +
		rawTestPublicKeyBase64(t, "torn-good") +
		`","alg":"ES256","rp_id":"stet","aaguid":"0102030405060708090a0b0c0d0e0f10","label":"x","at":"2026-01-02T03:04:05Z"}` + "\n"
	// No closing brace and no trailing newline: simulates a write that
	// stopped part-way through the next record.
	torn := `{"op":"add","credential_id":"partial`
	if err := os.WriteFile(path, []byte(good+torn), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load with an unterminated trailing record: %v, want it tolerated as not-yet-committed", err)
	}
	if _, state := set.Lookup([]byte("hello")); state != StateActive {
		t.Errorf("the earlier, complete record: state = %v, want StateActive", state)
	}
}

// The tests below cover round 4 of the same torn-write theme: Load must
// not drop a final unterminated line that is actually a complete,
// committed record (round-3 finding: a revoke without a trailing
// newline used to be silently ignored, so a revoked key kept verifying
// -- fail-open); and Add/Revoke must be able to recover from a genuinely
// uncommitted fragment on their own, in-package, rather than refusing
// forever (round-3 finding: no way to revoke a compromised key once the
// log ends in a torn fragment). See reloadLocked, terminateLocked and
// truncateLocked in trust.go for the recovery this exercises.

// TestAddCleansUpUnterminatedFragmentAndSucceeds replaces the old
// contract asserted by (the now-removed)
// TestAddRefusesToAppendPastUnterminatedTrailingLine: Add must no longer
// refuse forever when the file ends in an uncommitted fragment. It must
// truncate the fragment away (discarding only those never-committed
// bytes) and append the new record, so the log is loadable again and a
// user who says "revoke this compromised key" right after a torn write
// is not stuck.
func TestAddCleansUpUnterminatedFragmentAndSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	good := `{"op":"add","credential_id":"aGVsbG8","public_key":"` +
		rawTestPublicKeyBase64(t, "torn-good") +
		`","alg":"ES256","rp_id":"stet","aaguid":"0102030405060708090a0b0c0d0e0f10","label":"x","at":"2026-01-02T03:04:05Z"}` + "\n"
	// No closing brace and no trailing newline: this can never parse as
	// JSON, so by the commit rule it was never committed.
	torn := `{"op":"add","credential_id":"partial`
	if err := os.WriteFile(path, []byte(good+torn), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	entry := testEntry(t, "torn-new")
	if err := log.Add(entry); err != nil {
		t.Fatalf("Add after an uncommitted fragment: %v, want it to clean up and succeed", err)
	}

	on, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(on), "partial") {
		t.Errorf("the uncommitted fragment is still on disk: %q", on)
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load after the cleanup: %v, want the log to load cleanly", err)
	}
	if _, state := set.Lookup([]byte("hello")); state != StateActive {
		t.Errorf("the earlier, complete record: state = %v, want StateActive", state)
	}
	if _, state := set.Lookup(entry.CredentialID); state != StateActive {
		t.Errorf("the newly added record: state = %v, want StateActive", state)
	}
}

// TestLoadHonorsCompleteFinalLineMissingNewline covers the round-3
// fail-open finding directly: a final line that is a complete, valid
// record -- here a revoke -- must still be applied even without its
// trailing newline. Dropping it (the old behavior) let a revoked key
// verify as if still active.
func TestLoadHonorsCompleteFinalLineMissingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entry := testEntry(t, "yara")
	if err := log.Add(entry); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := log.Revoke(entry.CredentialID, "lost device"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Strip the file's final newline, simulating a complete record
	// written by something that doesn't append '\n', or an edit that
	// dropped it -- the revoke line itself is fully intact JSON.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if data[len(data)-1] != '\n' {
		t.Fatalf("test setup: expected the file to end in a newline before stripping it")
	}
	if err := os.WriteFile(path, data[:len(data)-1], 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load with a complete final revoke missing its newline: %v, want it honored", err)
	}
	if _, state := set.Lookup(entry.CredentialID); state != StateRevoked {
		t.Fatalf("state = %v, want StateRevoked (the revoke must not be dropped)", state)
	}

	err = set.VerifyAssertion(entry.RPID, &fido.Assertion{CredentialID: entry.CredentialID}, fido.VerifyOptions{})
	if !errors.Is(err, ErrRevokedKey) {
		t.Errorf("VerifyAssertion error = %v, want ErrRevokedKey", err)
	}
}

// TestAddTerminatesCompleteFinalLineMissingNewline is the write-side
// counterpart: Add/Revoke must recognize the same shape (a complete
// record missing only its newline) and repair it additively -- append
// the missing '\n' -- rather than treating it as a fragment to discard,
// which would silently lose a committed record.
func TestAddTerminatesCompleteFinalLineMissingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first := testEntry(t, "zack")
	if err := log.Add(first); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := os.WriteFile(path, data[:len(data)-1], 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	log2, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open (after stripping the trailing newline): %v", err)
	}
	defer func() { _ = log2.Close() }()

	second := testEntry(t, "yolanda")
	if err := log2.Add(second); err != nil {
		t.Fatalf("Add after a complete-but-unterminated final line: %v, want it repaired and to succeed", err)
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, state := set.Lookup(first.CredentialID); state != StateActive {
		t.Errorf("first (previously unterminated) record: state = %v, want StateActive", state)
	}
	if _, state := set.Lookup(second.CredentialID); state != StateActive {
		t.Errorf("second (newly appended) record: state = %v, want StateActive", state)
	}
}

// flakyWrite wraps an *os.File and, on its next Write call, physically
// writes only a truncated prefix of the given bytes to the underlying
// file before returning an error -- simulating a short write (e.g.
// ENOSPC) that lands a partial, uncommitted record on disk. It fires at
// most once.
type flakyWrite struct {
	*os.File
	failWriteOnce bool
}

func (w *flakyWrite) Write(p []byte) (int, error) {
	if w.failWriteOnce {
		w.failWriteOnce = false
		n := len(p) / 2
		if _, err := w.File.Write(p[:n]); err != nil {
			return 0, err
		}
		return n, errors.New("simulated short write")
	}
	return w.File.Write(p)
}

// TestAppendUndoesPartialWrite covers the appendLocked side of write
// failure: if Write itself lands only a prefix of the record on disk
// before failing, appendLocked must truncate that prefix back off
// immediately, so the file is left exactly as it was before the failed
// call -- not carrying a fragment for the next reloadLocked to have to
// clean up.
func TestAppendUndoesPartialWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	first := testEntry(t, "victor")
	if err := log.Add(first); err != nil {
		t.Fatalf("Add: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	log.w = &flakyWrite{File: log.f, failWriteOnce: true}
	second := testEntry(t, "uma")
	if err := log.Add(second); err == nil {
		t.Fatalf("Add: expected the simulated short write to surface")
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("file after a failed write = %q, want it truncated back to %q", after, before)
	}

	// A committed record is never lost across this path: the retry
	// (with a normal, non-flaky writer) must succeed, and Load must see
	// exactly the first record plus this retried one -- nothing missing,
	// nothing duplicated, no leftover fragment.
	log.w = log.f
	if err := log.Add(second); err != nil {
		t.Fatalf("Add (retry after the failed write): %v", err)
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, state := set.Lookup(first.CredentialID); state != StateActive {
		t.Errorf("first record: state = %v, want StateActive", state)
	}
	if _, state := set.Lookup(second.CredentialID); state != StateActive {
		t.Errorf("retried second record: state = %v, want StateActive", state)
	}
}

// flakyWriteAllButNewline wraps an *os.File and, on its next Write
// call, physically writes every byte except the record's trailing '\n'
// to the underlying file before returning an error -- unlike
// flakyWrite's cut-in-half fragment, the record's own bytes are already
// complete, valid JSON; only the terminator never landed. It fires at
// most once.
type flakyWriteAllButNewline struct {
	*os.File
	failWriteOnce bool
}

func (w *flakyWriteAllButNewline) Write(p []byte) (int, error) {
	if w.failWriteOnce {
		w.failWriteOnce = false
		n := len(p) - 1
		if _, err := w.File.Write(p[:n]); err != nil {
			return 0, err
		}
		return n, errors.New("simulated short write (newline never landed)")
	}
	return w.File.Write(p)
}

// TestAppendCommitsRecordWhenOnlyNewlineIsShort covers the round-4
// review finding: a short write that lands every byte of a record
// except its trailing '\n' has, by the commit rule (see the package
// doc), already produced a committed record -- a concurrent Load can
// see it mid-call, before appendLocked even returns. appendLocked must
// not truncate that record away just because the Write call that
// produced it reported an error, since doing so would delete a record
// that was already observably committed (here, silently reverting a
// revoke back to active). It must instead recognize the parseable tail,
// supply the missing terminator, and report the append as successful.
func TestAppendCommitsRecordWhenOnlyNewlineIsShort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	entry := testEntry(t, "penny")
	if err := log.Add(entry); err != nil {
		t.Fatalf("Add: %v", err)
	}

	log.w = &flakyWriteAllButNewline{File: log.f}
	if err := log.Revoke(entry.CredentialID, "lost device"); err != nil {
		t.Fatalf("Revoke: %v, want the all-but-newline short write to still be reported committed, not an error", err)
	}
	log.w = log.f

	on, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(on) == 0 || on[len(on)-1] != '\n' {
		t.Fatalf("file after the recovered write does not end in a newline: %q", on)
	}

	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v, want the log to remain valid", err)
	}
	if _, state := set.Lookup(entry.CredentialID); state != StateRevoked {
		t.Errorf("state = %v, want StateRevoked (a committed record must never be lost to a truncation)", state)
	}
}
