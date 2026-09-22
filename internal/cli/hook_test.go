package cli

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aashish/agentvault/internal/event"
)

func TestClaudeEventMapping(t *testing.T) {
	cases := []struct {
		name   string
		tool   string
		input  map[string]any
		action event.ActionType
		check  func(t *testing.T, ev event.Event)
	}{
		{"bash", "Bash", map[string]any{"command": "rm -rf /tmp/x"}, event.ActionShell,
			func(t *testing.T, ev event.Event) {
				if ev.Cmd != "rm" || ev.Raw != "rm -rf /tmp/x" || len(ev.Argv) != 3 || ev.Argv[1] != "-rf" {
					t.Errorf("cmd/raw/argv: %+v", ev)
				}
			}},
		{"write", "Write", map[string]any{"file_path": "/w/f.txt"}, event.ActionFSWrite,
			func(t *testing.T, ev event.Event) {
				if ev.Path != "/w/f.txt" {
					t.Errorf("path: %q", ev.Path)
				}
			}},
		{"read", "Read", map[string]any{"file_path": "/home/u/.ssh/id_rsa"}, event.ActionFSRead,
			func(t *testing.T, ev event.Event) {
				if ev.Path != "/home/u/.ssh/id_rsa" {
					t.Errorf("path: %q", ev.Path)
				}
			}},
		{"glob-defaults-cwd", "Glob", map[string]any{"pattern": "*.go"}, event.ActionFSRead,
			func(t *testing.T, ev event.Event) {
				if ev.Path != "/work" {
					t.Errorf("glob without path must fall back to cwd, got %q", ev.Path)
				}
			}},
		{"webfetch", "WebFetch", map[string]any{"url": "https://evil.example:8443/x?y=1"}, event.ActionNetEgress,
			func(t *testing.T, ev event.Event) {
				if ev.Host != "evil.example" || ev.Port != 443 {
					t.Errorf("host/port: %q:%d", ev.Host, ev.Port)
				}
			}},
		{"todowrite-normalized", "TodoWrite", map[string]any{"todos": []any{}}, event.ActionMCPTool,
			func(t *testing.T, ev event.Event) {
				if ev.Tool != "todowrite" {
					t.Errorf("tool name must be lowercased, got %q", ev.Tool)
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := claudeEvent(claudeHookInput{ToolName: c.tool, ToolInput: c.input, Cwd: "/work"})
			if ev.Action != c.action {
				t.Fatalf("action: got %s want %s", ev.Action, c.action)
			}
			if ev.Source != "claude-hook" {
				t.Errorf("source: %q", ev.Source)
			}
			c.check(t, ev)
		})
	}
}

func TestClaudeHookNoSessionAllows(t *testing.T) {
	t.Setenv("AGENTVAULT_SOCK", "")
	var errBuf bytes.Buffer
	in := strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"/work"}`)
	if code := runClaudeHook(in, &errBuf); code != hookAllow {
		t.Fatalf("standalone (no session) must allow, got exit %d", code)
	}
}

// fakeSupervisor answers eval requests with the given verdict.
func fakeSupervisor(t *testing.T, effect event.Effect, rule string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req event.EvalRequest
			_ = json.NewDecoder(conn).Decode(&req)
			_ = json.NewEncoder(conn).Encode(event.EvalResponse{
				Type: "verdict", Effect: effect, RuleName: rule, Message: "blocked for your protection",
			})
			_ = conn.Close()
		}
	}()
	return sock
}

func TestClaudeHookDenyBlocksWithExit2(t *testing.T) {
	t.Setenv("AGENTVAULT_SOCK", fakeSupervisor(t, event.Deny, "block-destructive-shell"))
	t.Setenv("AGENTVAULT_SESSION", "sess")
	var errBuf bytes.Buffer
	in := strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"/work"}`)
	if code := runClaudeHook(in, &errBuf); code != hookBlock {
		t.Fatalf("denied tool must exit 2, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "block-destructive-shell") {
		t.Errorf("stderr should name the rule (agent feedback), got %q", errBuf.String())
	}
}

func TestClaudeHookAllowExits0(t *testing.T) {
	t.Setenv("AGENTVAULT_SOCK", fakeSupervisor(t, event.Allow, ""))
	t.Setenv("AGENTVAULT_SESSION", "sess")
	in := strings.NewReader(`{"tool_name":"Read","tool_input":{"file_path":"/work/f.go"},"cwd":"/work"}`)
	if code := runClaudeHook(in, &bytes.Buffer{}); code != hookAllow {
		t.Fatalf("allowed tool must exit 0, got %d", code)
	}
}

func TestClaudeHookFailClosedOnIPCError(t *testing.T) {
	t.Setenv("AGENTVAULT_SOCK", filepath.Join(t.TempDir(), "nonexistent.sock"))
	in := strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/work"}`)
	var errBuf bytes.Buffer
	if code := runClaudeHook(in, &errBuf); code != hookBlock {
		t.Fatalf("dead supervisor must block (fail closed), got %d", code)
	}
	if !strings.Contains(errBuf.String(), "fail closed") {
		t.Errorf("stderr should explain the fail-closed block, got %q", errBuf.String())
	}
}

func TestMutateClaudeWritesPreToolUseHook(t *testing.T) {
	cfg := map[string]any{}
	mutateClaude(cfg, "/usr/local/bin/agentvault")
	hooks, ok := cfg["hooks"].(map[string]any)
	if !ok {
		t.Fatal("hooks key missing")
	}
	pre, ok := hooks["PreToolUse"].([]any)
	if !ok || len(pre) != 1 {
		t.Fatalf("PreToolUse: %v", hooks["PreToolUse"])
	}
	raw, _ := json.Marshal(pre[0])
	if !strings.Contains(string(raw), "agentvault hook claude") {
		t.Errorf("hook command missing: %s", raw)
	}

	// Idempotent: a second run must not duplicate the entry.
	mutateClaude(cfg, "/usr/local/bin/agentvault")
	pre = cfg["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("not idempotent: %d entries", len(pre))
	}

	// Existing user hooks survive.
	cfg2 := map[string]any{"hooks": map[string]any{
		"PreToolUse": []any{map[string]any{"matcher": "Bash", "hooks": []any{map[string]any{"type": "command", "command": "my-linter"}}}},
	}}
	mutateClaude(cfg2, "/usr/local/bin/agentvault")
	pre2 := cfg2["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre2) != 2 {
		t.Fatalf("existing hooks must be preserved, got %d entries", len(pre2))
	}
}

func TestIntegrateClaudeCLIEndToEnd(t *testing.T) {
	dir := t.TempDir()
	stdout, _, err := runCLI(t, "integrate", "claude", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Claude Code configured") {
		t.Errorf("output: %q", stdout)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("settings.json not written: %v", err)
	}
	if !strings.Contains(string(raw), "hook claude") {
		t.Errorf("settings.json missing hook: %s", raw)
	}
}
