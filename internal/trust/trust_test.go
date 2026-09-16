package trust

import (
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

func testEntry(label string) Entry {
	return Entry{
		CredentialID: []byte("cred-" + label),
		PublicKey:    []byte("pubkey-" + label),
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
	entry := testEntry("alice")
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

	entry := testEntry("bob")
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

	// Re-adding a revoked credential succeeds at the Log level (it is a
	// dumb appender) but must surface as a Load error.
	if err := log.Add(entry); err != nil {
		t.Fatalf("Add (re-add): %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("Load after re-adding a revoked credential: expected an error")
	}
}

func TestDuplicateAddIsLoadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	entry := testEntry("carol")
	if err := log.Add(entry); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := log.Add(entry); err != nil {
		t.Fatalf("Add (duplicate): %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatalf("Load with a duplicate add: expected an error")
	}
}

func TestRevokeUnknownCredentialIsLoadError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-keys.jsonl")

	log, err := Open(path, WithClock(fixedClock(time.Now())))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close() }()

	if err := log.Revoke([]byte("nobody"), "n/a"); err != nil {
		t.Fatalf("Revoke: %v", err)
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

	if err := log.Add(testEntry("dave")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if err := log.Add(testEntry("erin")); err != nil {
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
	if err := log1.Add(testEntry("frank")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	_ = log1.Close()

	path2 := filepath.Join(t.TempDir(), "b.jsonl")
	log2, err := Open(path2, WithClock(fixedClock(at)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := log2.Add(testEntry("frank")); err != nil {
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
