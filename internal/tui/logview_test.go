package tui

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aashish/agentvault/internal/audit"
	"github.com/aashish/agentvault/internal/event"
)

func seedStore(t *testing.T, recs []audit.Record) *audit.Store {
	t.Helper()
	store, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	sid := event.NewID()
	if err := store.BeginSession(sid, "test", []string{"x"}, nil); err != nil {
		t.Fatal(err)
	}
	lg, err := audit.NewLogger(store, filepath.Join(t.TempDir(), "overflow"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		lg.Log(r.Event, r.Verdict, r.Decision)
	}
	if err := lg.Flush(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	_ = lg.Close()
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func mkRecord(cmd, verdict, rule string) audit.Record {
	return audit.Record{
		Event: event.Event{
			ID: event.NewID(), Timestamp: time.Now().UTC(),
			Source: event.SourceShim, Action: event.ActionShell,
			Cmd: cmd, Argv: []string{cmd}, Raw: cmd, Cwd: "/work",
		},
		Verdict: event.Verdict{Effect: event.Effect(verdict), RuleName: rule},
	}
}

func TestRefreshAndFilters(t *testing.T) {
	store := seedStore(t, []audit.Record{
		mkRecord("ls", "allow", "allow-ls"),
		mkRecord("rm", "deny", "block-rm"),
		mkRecord("git", "deny", "ask-push"),
	})
	m := NewModel(store)
	m.refresh()
	if len(m.rows) != 3 || len(m.filtered) != 3 {
		t.Fatalf("want 3 rows, got %d/%d", len(m.rows), len(m.filtered))
	}

	// Verdict filter: deny only.
	m.verdictSel = "deny"
	m.applyFilter()
	if len(m.filtered) != 2 {
		t.Fatalf("deny filter: want 2, got %d", len(m.filtered))
	}

	// Text filter on top.
	m.filter = "rm"
	m.applyFilter()
	if len(m.filtered) != 1 {
		t.Fatalf("text filter: want 1, got %d", len(m.filtered))
	}
	if m.rows[m.filtered[0]].rule != "block-rm" {
		t.Fatalf("wrong row survived filter")
	}

	// Cycle verdict back to all.
	m.verdictSel = "deny"
	m.filter = ""
	m.cycleVerdict() // → require_approval
	m.cycleVerdict() // → ""
	if m.verdictSel != "" || len(m.filtered) != 3 {
		t.Fatalf("cycle broken: %q %d", m.verdictSel, len(m.filtered))
	}
}

func TestTableViewRendersBadges(t *testing.T) {
	store := seedStore(t, []audit.Record{mkRecord("rm", "deny", "block-rm")})
	m := NewModel(store)
	m.refresh()
	out := m.tableView()
	// Text badge must be present regardless of color support.
	if !strings.Contains(stripANSI(out), "[DENY]") {
		t.Fatalf("badge missing:\n%s", out)
	}
	if !strings.Contains(out, "block-rm") {
		t.Fatalf("rule missing:\n%s", out)
	}
}

func TestDetailView(t *testing.T) {
	store := seedStore(t, []audit.Record{mkRecord("rm", "deny", "block-rm")})
	m := NewModel(store)
	m.refresh()
	m.detail = true
	out := m.detailView()
	if !strings.Contains(out, "EVENT DETAIL") || !strings.Contains(out, `"cmd": "rm"`) {
		t.Fatalf("detail view broken:\n%s", out)
	}
}

func TestEmptyLog(t *testing.T) {
	store := seedStore(t, nil)
	m := NewModel(store)
	m.refresh()
	out := m.tableView()
	if !strings.Contains(out, "no events") {
		t.Fatalf("empty log must render placeholder:\n%s", out)
	}
}

// stripANSI removes CSI sequences for assertions on rendered text.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
