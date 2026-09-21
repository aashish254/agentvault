package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/event"
)

// ---- helpers ----

func engineFromYAML(t *testing.T, y string) Engine {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agentvault.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, _, err := config.Load(p)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	eng, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng
}

func baseEvent() event.Event {
	return event.Event{
		ID:        event.NewID(),
		SessionID: "test",
		Timestamp: time.Now().UTC(),
		Cwd:       "/work",
		PID:       1,
	}
}

func shellEvent(cmd string, argv ...string) event.Event {
	e := baseEvent()
	e.Source, e.Action = event.SourceShim, event.ActionShell
	e.Cmd = cmd
	e.Argv = append([]string{cmd}, argv...)
	e.Raw = cmd + " " + strings.Join(argv, " ")
	return e
}

func fsEvent(action event.ActionType, path string) event.Event {
	e := baseEvent()
	e.Source, e.Action, e.Path = event.SourceMCP, action, path
	return e
}

func netEvent(host string, port int) event.Event {
	e := baseEvent()
	e.Source, e.Action, e.Host, e.Port = event.SourceEgress, event.ActionNetEgress, host, port
	return e
}

func mcpEvent(server, tool string) event.Event {
	e := baseEvent()
	e.Source, e.Action, e.Server, e.Tool = event.SourceMCP, event.ActionMCPTool, server, tool
	return e
}
