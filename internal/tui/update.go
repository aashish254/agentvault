package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Update handles keys and poll ticks.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		m.refresh()
		return m, tea.Tick(pollInterval, tick)
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if m.filtering {
		switch key {
		case "enter":
			m.filtering = false
			m.applyFilter()
		case "esc":
			m.filtering = false
			m.filter = ""
			m.applyFilter()
		case "backspace":
			if len(m.filter) > 0 {
				m.filter = m.filter[:len(m.filter)-1]
			}
		default:
			if len(msg.Runes) > 0 {
				m.filter += string(msg.Runes)
			}
		}
		return m, nil
	}

	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		if m.detail {
			m.detail = false
		}
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.filtered)-1 {
			m.cursor++
		}
	case "enter":
		if len(m.filtered) > 0 {
			m.detail = !m.detail
		}
	case "/":
		m.filtering = true
	case "v":
		m.cycleVerdict()
	}
	return m, nil
}

// View renders the current state.
func (m Model) View() string {
	if m.err != nil {
		return fmt.Sprintf("agentvault log: %v\n", m.err)
	}
	if m.detail && len(m.filtered) > 0 {
		return m.detailView()
	}
	return m.tableView()
}

const pollInterval = 500 * time.Millisecond

func tick(t time.Time) tea.Msg { return tickMsg(t) }
