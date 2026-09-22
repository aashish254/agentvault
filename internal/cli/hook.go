package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aashish/agentvault/internal/event"
	"github.com/aashish/agentvault/internal/ipc"
)

// `agentvault hook claude` is Claude Code's PreToolUse hook endpoint:
// Claude pipes the tool call as JSON on stdin and interprets our exit
// code — 0 allows the tool, 2 blocks it (stderr is shown to Claude).
// Outside an agentvault session (no AGENTVAULT_SOCK) we allow silently,
// mirroring the opencode plugin's standalone behavior.

const (
	hookAllow = 0
	hookBlock = 2
)

// claudeHookInput is the PreToolUse payload Claude Code sends on stdin.
type claudeHookInput struct {
	SessionID string         `json:"session_id"`
	Cwd       string         `json:"cwd"`
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
}

func newHookCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "hook <claude>",
		Short:  "Agent hook endpoint (installed by 'agentvault integrate')",
		Hidden: true, // plumbing, not UX
		Args:   cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "claude":
				os.Exit(runClaudeHook(os.Stdin, cmd.ErrOrStderr()))
			default:
				fmt.Fprintf(cmd.ErrOrStderr(), "agentvault: unknown hook target %q\n", args[0])
				os.Exit(hookAllow) // never break an agent over our own misuse
			}
		},
	}
}

// runClaudeHook is the whole hook flow, factored for tests: read the
// tool call, map it to an AgentVault event, ask the supervisor, exit.
func runClaudeHook(stdin io.Reader, stderr io.Writer) int {
	var in claudeHookInput
	if err := json.NewDecoder(stdin).Decode(&in); err != nil {
		// Unparseable input: allow rather than wedge Claude, but say so.
		fmt.Fprintf(stderr, "agentvault: hook: bad input (%v) — allowing\n", err)
		return hookAllow
	}
	ev := claudeEvent(in)

	sock := os.Getenv("AGENTVAULT_SOCK")
	if sock == "" {
		return hookAllow // standalone Claude, no session — nothing to ask
	}
	resp, err := hookEval(sock, ev)
	if err != nil {
		fmt.Fprintf(stderr, "agentvault: policy check failed (%v) — blocking (fail closed)\n", err)
		return hookBlock
	}
	if resp.Effect == event.Allow {
		return hookAllow
	}
	fmt.Fprintf(stderr, "AgentVault: blocked by policy")
	if resp.RuleName != "" {
		fmt.Fprintf(stderr, " (%s)", resp.RuleName)
	}
	if resp.Message != "" {
		fmt.Fprintf(stderr, ": %s", resp.Message)
	}
	fmt.Fprintln(stderr)
	return hookBlock
}

// hookEval sends one eval request and awaits the verdict. The dial
// timeout is short (a dead supervisor must not hang the agent) but the
// read has no deadline: require_approval blocks server-side until the
// human answers or the approval timeout fires.
func hookEval(sock string, ev event.Event) (event.EvalResponse, error) {
	// #nosec G704 -- sock is our own session socket path from the supervisor.
	conn, err := net.DialTimeout("unix", sock, 500*time.Millisecond)
	if err != nil {
		return event.EvalResponse{}, err
	}
	defer func() { _ = conn.Close() }()
	req := event.EvalRequest{Type: "eval", Token: ipc.EnvToken(), Event: ev}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return event.EvalResponse{}, err
	}
	var resp event.EvalResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return event.EvalResponse{}, err
	}
	if resp.Type != "verdict" {
		return event.EvalResponse{}, fmt.Errorf("unexpected response %q", resp.Type)
	}
	return resp, nil
}

// claudeEvent maps a Claude Code tool call onto the canonical event.
// Tool names are lowercased so one policy rule set (e.g. the default
// allow-benign-agent-tools) covers opencode and Claude alike.
func claudeEvent(in claudeHookInput) event.Event {
	tool := strings.ToLower(in.ToolName)
	ev := event.Event{
		ID:        event.NewID(),
		SessionID: os.Getenv("AGENTVAULT_SESSION"),
		Timestamp: time.Now().UTC(),
		Source:    "claude-hook",
		Action:    event.ActionMCPTool,
		Tool:      tool,
		Cwd:       in.Cwd,
		PID:       os.Getpid(),
	}
	if ev.Cwd == "" {
		ev.Cwd, _ = os.Getwd()
	}
	arg := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := in.ToolInput[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	switch tool {
	case "bash":
		ev.Action = event.ActionShell
		ev.Raw = arg("command")
		ev.Argv = strings.Fields(ev.Raw) // policies inspect argv[1] (e.g. git push)
		ev.Cmd = firstWord(ev.Raw)
	case "write", "edit", "multiedit", "notebookedit":
		ev.Action = event.ActionFSWrite
		ev.Path = arg("file_path", "notebook_path")
	case "read":
		ev.Action = event.ActionFSRead
		ev.Path = arg("file_path")
	case "glob", "grep", "ls":
		// Read-only navigation: path-governed like the opencode mapping.
		ev.Action = event.ActionFSRead
		if ev.Path = arg("path"); ev.Path == "" {
			ev.Path = ev.Cwd
		}
	case "webfetch":
		ev.Action = event.ActionNetEgress
		ev.Host = hostOf(arg("url"))
		ev.Port = 443
	}
	return ev
}

func firstWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// hostOf extracts the host from a URL without net/url's error surface
// (a hook must never fail open OR closed because of URL oddities).
func hostOf(raw string) string {
	h := strings.TrimPrefix(raw, "https://")
	h = strings.TrimPrefix(h, "http://")
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return h
}
