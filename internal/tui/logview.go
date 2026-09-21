// Package tui implements `agentvault log`: a live-tailing, filterable
// view of the audit log (SPEC §4.6). It reads SQLite directly — the
// supervisor and the TUI share the DB file, no extra IPC.
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aashish/agentvault/internal/audit"
)

// row is one rendered audit record (pre-computed for fast filtering).
type row struct {
	ts      string
	action  string
	target  string
	verdict string // final outcome (decision final_effect when present)
	rule    string
	raw     audit.Record
}

// tickMsg polls the store for new rows.
type tickMsg time.Time

// Model is the BubbleTea model for the log view.
type Model struct {
	store      *audit.Store
	rows       []row
	filtered   []int // indices into rows
	filter     string
	verdictSel string // "", "allow", "deny", "require_approval"
	cursor     int
	detail     bool
	width      int
	height     int
	filtering  bool
	err        error
}

// NewModel builds the model over an open store.
func NewModel(store *audit.Store) Model {
	return Model{store: store, width: 100, height: 30}
}

// Init kicks off the poll loop.
func (m Model) Init() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// targetOf renders the event's human target.
func targetOf(r audit.Record) string {
	e := r.Event
	switch {
	case e.Raw != "":
		return "$ " + e.Raw
	case e.Path != "":
		return e.Path
	case e.Host != "":
		return fmt.Sprintf("%s:%d", e.Host, e.Port)
	case e.Tool != "":
		return fmt.Sprintf("%s/%s", e.Server, e.Tool)
	default:
		return string(e.Action)
	}
}

// finalEffect returns the decision outcome when present, else verdict.
func finalEffect(r audit.Record) string {
	if r.Decision != nil && r.Decision.FinalEffect != "" {
		return string(r.Decision.FinalEffect)
	}
	return string(r.Verdict.Effect)
}

// refresh loads rows from the store and reapplies filters.
func (m *Model) refresh() {
	recs, err := m.store.Query(audit.QueryOpts{})
	if err != nil {
		m.err = err
		return
	}
	m.rows = m.rows[:0]
	for _, r := range recs {
		m.rows = append(m.rows, row{
			ts:      r.Event.Timestamp.Local().Format("15:04:05"),
			action:  string(r.Event.Action),
			target:  targetOf(r),
			verdict: finalEffect(r),
			rule:    r.Verdict.RuleName,
			raw:     r,
		})
	}
	m.applyFilter()
}

// applyFilter recomputes the visible row set.
func (m *Model) applyFilter() {
	m.filtered = m.filtered[:0]
	f := strings.ToLower(m.filter)
	for i, r := range m.rows {
		if m.verdictSel != "" && r.verdict != m.verdictSel {
			continue
		}
		if f != "" && !strings.Contains(strings.ToLower(r.action+" "+r.target+" "+r.rule), f) {
			continue
		}
		m.filtered = append(m.filtered, i)
	}
	if m.cursor >= len(m.filtered) {
		m.cursor = max(0, len(m.filtered)-1)
	}
}

// cycleVerdict advances the verdict filter: all → allow → deny → ask.
func (m *Model) cycleVerdict() {
	order := []string{"", "allow", "deny", "require_approval"}
	cur := 0
	for i, v := range order {
		if v == m.verdictSel {
			cur = i
		}
	}
	m.verdictSel = order[(cur+1)%len(order)]
	m.applyFilter()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
