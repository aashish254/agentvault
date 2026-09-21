// Package mcp implements the MCP stdio proxy (SPEC §4.2): it poses as an
// MCP server toward the agent and proxies to the real server, evaluating
// every tools/call against the session policy. All other traffic passes
// through byte-identical.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// msg is the minimal JSON-RPC 2.0 header we parse. Raw keeps the exact
// original bytes for passthrough.
type msg struct {
	Raw    json.RawMessage // exact original line bytes (sans newline)
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params *callParams     `json:"params,omitempty"`
}

// callParams is only fully populated for tools/call; other methods leave
// it nil or with zero fields.
type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// framing: MCP stdio transport is newline-delimited JSON-RPC 2.0 —
// one complete message per line, no embedded newlines (MCP spec).
type framer struct {
	r *bufio.Reader
}

func newFramer(r io.Reader) *framer {
	return &framer{r: bufio.NewReaderSize(r, 1<<20)}
}

// next reads one line. Returns io.EOF at stream end.
func (f *framer) next() ([]byte, error) {
	line, err := f.r.ReadBytes('\n')
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if err == io.EOF && len(line) > 0 {
		return line, nil // final line without trailing newline
	}
	return line, err
}

// parseMsg extracts the header. Malformed lines yield an error and nil;
// the caller decides policy (we forward verbatim — the real server
// produces the parse error, keeping us transparent).
func parseMsg(line []byte) (*msg, error) {
	m := &msg{Raw: append([]byte(nil), line...)}
	if err := json.Unmarshal(line, m); err != nil {
		return nil, err
	}
	return m, nil
}

// isToolCall reports whether the message is a tools/call request.
func (m *msg) isToolCall() bool {
	return m.Method == "tools/call" && m.Params != nil && m.ID != nil
}

// denyResponse synthesizes a JSON-RPC error for a blocked tool call.
// The agent sees an ordinary tool error and can adapt (SPEC §1.4).
func denyResponse(id json.RawMessage, rule, message string) []byte {
	text := fmt.Sprintf("blocked by AgentVault policy: %s", rule)
	if message != "" {
		text += " — " + message
	}
	out, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error":   map[string]any{"code": -32000, "message": text},
	})
	if err != nil {
		// id should always be valid JSON; fall back to null id.
		out = []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"blocked by AgentVault policy"}}`)
	}
	return out
}
