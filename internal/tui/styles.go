package tui

import "github.com/charmbracelet/lipgloss"

// Color-blind safety: verdicts are text badges first, colors second.
var (
	styleAllow = lipgloss.NewStyle().Foreground(lipgloss.Color("10")) // green
	styleDeny  = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))  // red
	styleAsk   = lipgloss.NewStyle().Foreground(lipgloss.Color("11")) // yellow
	styleDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleHead  = lipgloss.NewStyle().Bold(true)
	styleCurs  = lipgloss.NewStyle().Reverse(true)
)

// badge renders the verdict as a text badge (never color alone).
func badge(effect string) string {
	switch effect {
	case "allow":
		return styleAllow.Render("[ALLOW]")
	case "deny":
		return styleDeny.Render("[DENY] ")
	default:
		return styleAsk.Render("[ASK]  ")
	}
}
