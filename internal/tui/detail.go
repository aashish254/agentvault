package tui

import (
	"encoding/json"
	"fmt"
	"strings"
)

// tableView renders the filterable, live-tailing event table.
func (m Model) tableView() string {
	var b strings.Builder
	header := styleHead.Render("AGENTVAULT LOG")
	status := styleDim.Render(fmt.Sprintf(
		"%d events · verdict:%s · / filter · v verdict · enter detail · q quit",
		len(m.filtered), orAll(m.verdictSel)))
	b.WriteString(header + "  " + status + "\n")
	if m.filtering || m.filter != "" {
		b.WriteString(styleDim.Render("filter: ") + m.filter + "\n")
	}

	if len(m.filtered) == 0 {
		b.WriteString(styleDim.Render("  no events") + "\n")
		return b.String()
	}

	// Visible window: keep the cursor centered.
	visible := m.height - 4
	if visible < 3 {
		visible = 3
	}
	start := 0
	if m.cursor >= visible {
		start = m.cursor - visible + 1
	}
	end := start + visible
	if end > len(m.filtered) {
		end = len(m.filtered)
	}
	for i := start; i < end; i++ {
		r := m.rows[m.filtered[i]]
		line := fmt.Sprintf(" %s  %-10s %s  %-24s %s",
			r.ts, r.action, badge(r.verdict), trunc(r.rule, 24), trunc(r.target, m.width-60))
		if i == m.cursor {
			line = styleCurs.Render(line)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// detailView renders the full record for the selected row.
func (m Model) detailView() string {
	r := m.rows[m.filtered[m.cursor]].raw
	var b strings.Builder
	b.WriteString(styleHead.Render("EVENT DETAIL") + styleDim.Render("  (esc/enter back)") + "\n\n")
	fmt.Fprintf(&b, "  verdict: %s   rule: %s\n", badge(finalEffect(r)), orNone(r.Verdict.RuleName))
	if r.Decision != nil {
		fmt.Fprintf(&b, "  approved_by: %s   waited: %s   timed_out: %v\n",
			orNone(r.Decision.ApprovedBy), r.Decision.Waited, r.Decision.TimedOut)
	}
	fmt.Fprintf(&b, "  eval: %dµs   source: %s\n\n", r.Verdict.EvalMicros, r.Event.Source)
	payload, err := json.MarshalIndent(r.Event, "  ", "  ")
	if err != nil {
		payload = []byte(fmt.Sprintf("%+v", r.Event))
	}
	b.WriteString("  " + string(payload) + "\n")
	return b.String()
}

func orAll(s string) string {
	if s == "" {
		return "all"
	}
	return s
}

func orNone(s string) string {
	if s == "" {
		return "(default)"
	}
	return s
}

func trunc(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:max(0, n-1)] + "…"
}
