package mcp

import (
	"encoding/json"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// toolActions maps well-known MCP filesystem-server tool names onto the
// fs.* action vocabulary so path rules apply to MCP tool calls. Unknown
// tools stay mcp.tool.
var toolActions = map[string]event.ActionType{
	"read_file":        event.ActionFSRead,
	"read_text_file":   event.ActionFSRead,
	"list_directory":   event.ActionFSRead,
	"write_file":       event.ActionFSWrite,
	"edit_file":        event.ActionFSWrite,
	"create_directory": event.ActionFSWrite,
	"delete_file":      event.ActionFSDelete,
	"remove_directory": event.ActionFSDelete,
	"move_file":        event.ActionFSDelete, // destructive on the source
}

// buildEvent maps a tools/call message to an InterceptedEvent.
func buildEvent(server string, m *msg) event.Event {
	e := event.Event{
		ID:        event.NewID(),
		SessionID: sessionFromEnv(),
		Timestamp: time.Now().UTC(),
		Source:    event.SourceMCP,
		Action:    event.ActionMCPTool,
		Server:    server,
		Tool:      m.Params.Name,
		ToolArgs:  m.Params.Arguments,
		Cwd:       cwdOf(),
		PID:       pidOf(),
	}
	if action, ok := toolActions[m.Params.Name]; ok {
		e.Action = action
	}
	// Filesystem tools carry their target in arguments.path (or .source
	// for move_file).
	var args struct {
		Path   string `json:"path"`
		Source string `json:"source"`
	}
	if len(m.Params.Arguments) > 0 {
		if json.Unmarshal(m.Params.Arguments, &args) == nil {
			switch {
			case args.Path != "":
				e.Path = args.Path
			case args.Source != "":
				e.Path = args.Source
			}
		}
	}
	return e
}
