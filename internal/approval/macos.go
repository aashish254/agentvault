package approval

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// MacOSChannel pops a native macOS dialog (via osascript) for each
// approval request. The agent is frozen while the dialog is up and the
// human clicks Allow Once / Always Allow / Deny — for people who don't
// watch the terminal the agent runs in. The dialog explains WHAT the
// agent wants and WHAT COULD HAPPEN, because a decision without stakes
// is just a button mash.
type MacOSChannel struct {
	run func(ctx context.Context, script string) (string, error) // test seam
}

// NewMacOS returns a dialog channel, or nil off macOS / without osascript
// (auto-disable, mirroring NewTTY's no-terminal behavior).
func NewMacOS() *MacOSChannel {
	if runtime.GOOS != "darwin" {
		return nil
	}
	if _, err := exec.LookPath("osascript"); err != nil {
		return nil
	}
	return &MacOSChannel{run: runOsascript}
}

// newMacOSWith injects the script runner (tests).
func newMacOSWith(run func(context.Context, string) (string, error)) *MacOSChannel {
	return &MacOSChannel{run: run}
}

func (m *MacOSChannel) Name() string { return "macos-dialog" }

func (m *MacOSChannel) Ask(ctx Context, r Request) (<-chan Response, error) {
	resp := make(chan Response, 1)
	// Give the human a slightly shorter fuse than the IPC timeout so an
	// answer lands before the daemon denies on expiry.
	secs := int(time.Until(r.ExpiresAt).Seconds()) - 2
	if secs < 5 {
		secs = 5
	}
	if secs > 300 {
		secs = 300
	}
	script := dialogScript(r, secs)
	go func() {
		out, err := m.run(ctx, script)
		if err != nil {
			return // dismissed/errored/gave up -> daemon timeout denies (fail closed)
		}
		switch {
		case strings.Contains(out, "Always Allow"):
			resp <- Response{Allow: true, AllowRule: true, By: "macos-dialog"}
		case strings.Contains(out, "Allow Once"):
			resp <- Response{Allow: true, By: "macos-dialog"}
		default:
			resp <- Response{Allow: false, By: "macos-dialog"}
		}
	}()
	return resp, nil
}

func (m *MacOSChannel) NotifyResolved(eventID string, outcome string) {
	// Best effort only: an osascript dialog can't be dismissed remotely.
	// A click on a stale dialog is ignored — the daemon already resolved.
}

// dialogScript renders the AppleScript. Deny is both the default and the
// cancel button; the dialog self-dismisses (=> deny) on timeout.
func dialogScript(r Request, timeoutSecs int) string {
	body := fmt.Sprintf("Rule: %s\n\n%s\n\nDirectory: %s", r.RuleName, r.Summary(), r.Event.Cwd)
	if hint := riskHint(r); hint != "" {
		body += "\n\n⚠ " + hint
	}
	return fmt.Sprintf(`display dialog %s with title "AgentVault — agent requests permission"`+
		` buttons {"Deny", "Allow Once", "Always Allow"} default button "Deny" cancel button "Deny"`+
		` with icon caution giving up after %d`, appleQuote(body), timeoutSecs)
}

// riskHint states, in one line, what could go wrong — decision-making
// power requires knowing the stakes, not just the action.
func riskHint(r Request) string {
	switch r.Event.Action {
	case event.ActionShell:
		return "Shell commands run with YOUR full permissions — they can read, change, delete, or upload anything you can."
	case event.ActionNetEgress:
		return "Network access can SEND data out of this machine — anything the agent has already read (code, secrets, files) could be uploaded to this host."
	case event.ActionFSWrite:
		return "This writes or modifies a file on disk — the previous contents may be unrecoverable."
	case event.ActionFSRead:
		return "This reads a file's contents — the agent (and any service it talks to) will know what's inside."
	case event.ActionMCPTool:
		return "This invokes an external tool — its effect depends on the tool and isn't visible to AgentVault beyond this call."
	default:
		return ""
	}
}

// appleQuote escapes s for embedding in an AppleScript string literal,
// turning embedded newlines into ` & return & ` concatenations.
func appleQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `" & return & "`)
	return `"` + s + `"`
}

func runOsascript(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "osascript", "-e", script) // #nosec G204 -- fixed binary, script is our own literal
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}
