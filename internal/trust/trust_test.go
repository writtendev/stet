package trust

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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
