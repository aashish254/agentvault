// Package event defines the canonical InterceptedEvent produced by every
// interception channel, plus its deterministic serialization for hashing.
package event

import (
	"encoding/json"
	"time"

	"github.com/oklog/ulid/v2"
)

// ActionType is the normalized action vocabulary across all channels.
type ActionType string

const (
	ActionFSRead    ActionType = "fs.read"
	ActionFSWrite   ActionType = "fs.write"
	ActionFSDelete  ActionType = "fs.delete"
	ActionShell     ActionType = "shell.exec"
	ActionNetEgress ActionType = "net.egress"
	ActionMCPTool   ActionType = "mcp.tool"
)

// Source identifies which interception channel produced the event.
type Source string

const (
	SourceMCP    Source = "mcp"
	SourceShim   Source = "shim"
	SourceEgress Source = "egress"
)

// Event is the single canonical payload every channel must build.
// Zero-valued optional fields are omitted from CanonicalJSON.
type Event struct {
	ID        string     `json:"id" yaml:"id"` // ULID, generated at interception
	SessionID string     `json:"session_id" yaml:"session_id"`
	Timestamp time.Time  `json:"ts" yaml:"ts"` // UTC, RFC3339Nano in JSON
	Source    Source     `json:"source" yaml:"source"`
	Action    ActionType `json:"action" yaml:"action"`

	// shell.exec
	Cmd  string   `json:"cmd,omitempty" yaml:"cmd,omitempty"` // basename: "rm"
	Argv []string `json:"argv,omitempty" yaml:"argv,omitempty"`
	Raw  string   `json:"raw,omitempty" yaml:"raw,omitempty"` // full joined command line

	// fs.* and MCP filesystem tools
	Path string `json:"path,omitempty" yaml:"path,omitempty"` // absolute, ~ expanded, symlink-resolved

	// net.egress
	Host string `json:"host,omitempty" yaml:"host,omitempty"`
	Port int    `json:"port,omitempty" yaml:"port,omitempty"`

	// mcp.tool
	Server   string          `json:"server,omitempty" yaml:"server,omitempty"`
	Tool     string          `json:"tool,omitempty" yaml:"tool,omitempty"`
	ToolArgs json.RawMessage `json:"tool_args,omitempty" yaml:"tool_args,omitempty"`

	Cwd string            `json:"cwd" yaml:"cwd"`
	Env map[string]string `json:"-" yaml:"-"` // NEVER serialized or logged (secret leakage)
	PID int               `json:"pid" yaml:"pid"`
}

// NewID returns a fresh ULID string.
func NewID() string { return ulid.Make().String() }

// CanonicalJSON returns deterministic JSON used for audit-chain hashing.
// Go's encoding/json marshals struct fields in declaration order and map
// keys sorted, so output is byte-stable. Env MUST NOT be included.
func (e Event) CanonicalJSON() []byte {
	e.Env = nil // belt and braces: never hash secrets
	b, err := json.Marshal(e)
	if err != nil {
		// Event contains no channels/funcs; this is unreachable in practice.
		panic("event: canonical marshal failed: " + err.Error())
	}
	return b
}
