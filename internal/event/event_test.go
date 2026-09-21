package event

import (
	"strings"
	"testing"
	"time"
)

func TestCanonicalJSONIsDeterministicAndOmitsEnv(t *testing.T) {
	e := Event{
		ID:        "01JEXAMPLE0000000000000000",
		SessionID: "s1",
		Timestamp: time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC),
		Source:    SourceShim,
		Action:    ActionShell,
		Cmd:       "git",
		Argv:      []string{"git", "push", "origin", "main"},
		Cwd:       "/tmp/x",
		Env:       map[string]string{"AWS_SECRET_ACCESS_KEY": "hunter2"},
		PID:       4242,
	}
	a := e.CanonicalJSON()
	b := e.CanonicalJSON()
	if string(a) != string(b) {
		t.Fatal("canonical JSON not deterministic")
	}
	if strings.Contains(string(a), "hunter2") || strings.Contains(string(a), "AWS_SECRET") {
		t.Fatal("canonical JSON leaked env")
	}
	if !strings.Contains(string(a), `"cmd":"git"`) {
		t.Fatalf("canonical JSON missing fields: %s", a)
	}
}

func TestNewIDFormat(t *testing.T) {
	id := NewID()
	if len(id) != 26 {
		t.Fatalf("ULID length = %d, want 26", len(id))
	}
	if id == NewID() {
		t.Fatal("ULIDs collide")
	}
}
