package audit

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetentionArchivesAndDeletes(t *testing.T) {
	// Two sessions: one old (ended 100 days ago), one fresh.
	path, oldSID := newSealedStore(t, 10)
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	freshSID := "fresh"
	if err := store.BeginSession(freshSID, "agent", []string{"x"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.SignAndClose(); err != nil {
		t.Fatal(err)
	}
	// Age the old session.
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sessions SET ended_at='2000-01-01T00:00:00Z' WHERE id=?`, oldSID); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	archived, warnings, err := store.Retain(90)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Retain: %v warnings=%v", err, warnings)
	}
	if archived != 1 {
		t.Fatalf("archived = %d, want 1", archived)
	}

	// Archive file exists with header + 10 events.
	b, err := os.ReadFile(filepath.Join(filepath.Dir(path), "archive", oldSID+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 11 || !strings.Contains(lines[0], "agentvault-archive-header") {
		t.Fatalf("archive has %d lines, want 11 with header", len(lines))
	}
	// Old session rows are gone; fresh session is untouched and verifies.
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM events WHERE session_id=?`, oldSID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("old session rows remain: %d", n)
	}
	if err := store.Verify(freshSID); err != nil {
		t.Fatalf("fresh session must still verify: %v", err)
	}
	_ = store.Close()
}

func TestRetentionKeepsTamperedSessions(t *testing.T) {
	path, sid := newSealedStore(t, 10)
	tamper(t, path, `UPDATE sessions SET ended_at='2000-01-01T00:00:00Z'`)
	tamper(t, path, `UPDATE events SET verdict='deny' WHERE seq=3`)

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	archived, warnings, err := store.Retain(90)
	if err != nil {
		t.Fatal(err)
	}
	if archived != 0 || len(warnings) != 1 {
		t.Fatalf("tampered session must be kept: archived=%d warnings=%v", archived, warnings)
	}
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM events WHERE session_id=?`, sid).Scan(&n); err != nil || n != 10 {
		t.Fatalf("tampered evidence must remain: %d rows", n)
	}
}

func TestRetentionZeroKeepsForever(t *testing.T) {
	path, _ := newSealedStore(t, 5)
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	archived, _, err := store.Retain(0)
	if err != nil || archived != 0 {
		t.Fatalf("retention=0 must keep everything: %d %v", archived, err)
	}
}
