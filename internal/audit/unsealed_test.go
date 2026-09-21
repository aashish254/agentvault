package audit

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// A session killed before sealing must verify as ErrUnsealed, NOT as a
// tamper error — a crash is not an attack, and crying wolf trains users
// to ignore real tamper alarms.
func TestUnsealedSessionIsNotTampered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sid := event.NewID()
	if err := store.BeginSession(sid, "test", []string{"x"}, nil); err != nil {
		t.Fatal(err)
	}
	lg, err := NewLogger(store, path+".overflow")
	if err != nil {
		t.Fatal(err)
	}
	lg.Log(event.Event{
		ID: event.NewID(), SessionID: sid, Timestamp: time.Now().UTC(),
		Source: event.SourceShim, Action: event.ActionShell, Cmd: "ls", Cwd: "/tmp",
	}, event.Verdict{Effect: event.Allow, RuleName: "r"}, nil)
	if err := lg.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	_ = lg.Close()
	// Simulate a kill: close WITHOUT SignAndClose (no seal written).
	_ = store.db.Close()

	store2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store2.Close() }()
	err = store2.Verify(sid)
	if err == nil {
		t.Fatal("unsealed session must not verify OK")
	}
	if !errors.Is(err, ErrUnsealed) {
		t.Fatalf("unsealed session must return ErrUnsealed, got: %v", err)
	}
	var ue *UnsealedError
	if !errors.As(err, &ue) || ue.LastSeq != 0 {
		t.Fatalf("expected UnsealedError with LastSeq=0, got: %v", err)
	}
}
