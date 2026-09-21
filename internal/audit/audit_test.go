package audit

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// newSealedStore creates a store with one sealed session of n events.
func newSealedStore(t *testing.T, n int) (path, sessionID string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sessionID = event.NewID()
	if err := store.BeginSession(sessionID, "test-agent", []string{"agent"}, []byte("policy-bytes")); err != nil {
		t.Fatal(err)
	}
	lg, err := NewLogger(store, path+".overflow")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		e := event.Event{
			ID: event.NewID(), SessionID: sessionID, Timestamp: time.Now().UTC(),
			Source: event.SourceShim, Action: event.ActionShell,
			Cmd: fmt.Sprintf("cmd-%d", i), Argv: []string{"x"}, Cwd: "/tmp",
		}
		lg.Log(e, event.Verdict{Effect: event.Allow, RuleName: "r", EvalMicros: 5}, nil)
	}
	if err := lg.Flush(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := lg.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil { // seals + signs
		t.Fatal(err)
	}
	return path, sessionID
}

func openAndVerify(t *testing.T, path, sessionID string) error {
	t.Helper()
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	return store.Verify(sessionID)
}

func TestVerifyIntactSession(t *testing.T) {
	path, sid := newSealedStore(t, 50)
	if err := openAndVerify(t, path, sid); err != nil {
		t.Fatalf("intact session must verify: %v", err)
	}
}

// tamper applies a mutation to the DB file directly.
func tamper(t *testing.T, path string, sqlStmt string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(sqlStmt); err != nil {
		t.Fatalf("tamper %q: %v", sqlStmt, err)
	}
}

func TestTamperMatrix(t *testing.T) {
	cases := []struct {
		name string
		stmt string // %s = session id
	}{
		{"edit payload", `UPDATE events SET payload='{"hacked":true}' WHERE seq=5`},
		{"edit verdict", `UPDATE events SET verdict='deny' WHERE seq=5`},
		{"delete middle row", `DELETE FROM events WHERE seq=7`},
		{"delete suffix", `DELETE FROM events WHERE seq>=40`},
		{"reorder rows", `UPDATE events SET seq=seq+10000 WHERE seq=3`},
		{"edit rule name", `UPDATE events SET rule_name='innocent' WHERE seq=2`},
		{"edit signature", `UPDATE sessions SET head_sig=x'00'`},
		{"edit timestamp", `UPDATE events SET ts='2020-01-01T00:00:00Z' WHERE seq=9`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, sid := newSealedStore(t, 50)
			tamper(t, path, strings.ReplaceAll(tc.stmt, "%s", sid))
			err := openAndVerify(t, path, sid)
			if err == nil {
				t.Fatalf("tampering %q was NOT detected — chain is broken!", tc.name)
			}
		})
	}
}

func TestVerifyMissingSession(t *testing.T) {
	path, _ := newSealedStore(t, 1)
	if err := openAndVerify(t, path, "01DOESNOTEXIST0000000000000"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestSoak10kEvents(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test")
	}
	path, sid := newSealedStore(t, 10000)
	if err := openAndVerify(t, path, sid); err != nil {
		t.Fatalf("10k-event chain must verify: %v", err)
	}
	// No record may have spilled: channel + greedy batching must keep up.
	if b, err := os.ReadFile(path + ".overflow"); err == nil && len(bytes.TrimSpace(b)) > 0 {
		t.Fatalf("overflow file is not empty — %d bytes of records spilled", len(b))
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	recs, err := store.Query(QueryOpts{SessionID: sid})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 10000 {
		t.Fatalf("want 10000 records, got %d", len(recs))
	}
}

func TestQueryFilters(t *testing.T) {
	path, sid := newSealedStore(t, 20)
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	all, err := store.Query(QueryOpts{SessionID: sid})
	if err != nil || len(all) != 20 {
		t.Fatalf("all: %d %v", len(all), err)
	}
	denied, err := store.Query(QueryOpts{SessionID: sid, Verdict: "deny"})
	if err != nil || len(denied) != 0 {
		t.Fatalf("deny filter: %d %v", len(denied), err)
	}
	allowed, err := store.Query(QueryOpts{SessionID: sid, Verdict: "allow"})
	if err != nil || len(allowed) != 20 {
		t.Fatalf("allow filter: %d %v", len(allowed), err)
	}
	limited, err := store.Query(QueryOpts{SessionID: sid, Limit: 5})
	if err != nil || len(limited) != 5 {
		t.Fatalf("limit: %d %v", len(limited), err)
	}
	shell, err := store.Query(QueryOpts{SessionID: sid, Action: "shell.exec"})
	if err != nil || len(shell) != 20 {
		t.Fatalf("action filter: %d %v", len(shell), err)
	}
	future, err := store.Query(QueryOpts{SessionID: sid, Since: time.Hour})
	if err != nil || len(future) != 20 {
		t.Fatalf("since=1h should include all: %d %v", len(future), err)
	}
	ancient, err := store.Query(QueryOpts{SessionID: sid, Since: time.Nanosecond})
	if err != nil || len(ancient) > 20 {
		t.Fatalf("since=1ns: %d %v", len(ancient), err)
	}
}

func TestPolicyHashAttribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sid := event.NewID()
	if err := store.BeginSession(sid, "agent", []string{"x"}, []byte("the-policy")); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err := store.db.QueryRow(`SELECT policy_hash FROM sessions WHERE id=?`, sid).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash != policyHashOf([]byte("the-policy")) {
		t.Fatalf("policy hash mismatch: %s", hash)
	}
	_ = store.Close()
}
