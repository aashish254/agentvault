package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/aashish/agentvault/internal/event"
	"github.com/aashish/agentvault/internal/ipc"
	"github.com/aashish/agentvault/internal/proxy/mcp"
)

func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "MCP server wrapping (channel 1: tool calls)",
	}
	cmd.AddCommand(newMCPProxyCmd())
	return cmd
}

func newMCPProxyCmd() *cobra.Command {
	var serverName string
	c := &cobra.Command{
		Use:   "proxy --server <name> -- <real server command...>",
		Short: "Wrap a real MCP server: tools/call is policy-checked, all else passes through",
		Long: `Run an MCP server through AgentVault. Configure your agent to use
this command as the MCP server; every tools/call is evaluated against
the running session's policy (and may trigger an approval request),
while all other JSON-RPC traffic passes through byte-identical.

Without a live agentvault session (AGENTVAULT_SOCK/ADDR unset),
tools/call fails closed with a JSON-RPC error.`,
		Example: `  agentvault mcp proxy --server filesystem -- npx -y @modelcontextprotocol/server-filesystem .`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverName == "" {
				serverName = "unnamed"
			}
			p := &mcp.Proxy{
				ServerName: serverName,
				Command:    args,
				Eval:       ipcEval,
			}
			return p.Run()
		},
	}
	c.Flags().StringVar(&serverName, "server", "", "logical server name recorded in the audit log")
	return c
}

// ipcEval evaluates an event against the running session's supervisor.
// No session → fail closed with a clear message.
func ipcEval(e event.Event) event.Verdict {
	conn, err := ipc.DialEnv(500 * time.Millisecond)
	if err != nil {
		return event.Verdict{
			Effect:  event.Deny,
			Message: "no live agentvault session (fail closed): " + err.Error(),
		}
	}
	defer func() { _ = conn.Close() }()
	if err := json.NewEncoder(conn).Encode(event.EvalRequest{
		Type: "eval", Token: ipc.EnvToken(), Event: e,
	}); err != nil {
		return event.Verdict{Effect: event.Deny, Message: "eval send failed (fail closed)"}
	}
	var resp event.EvalResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil || resp.Type != "verdict" {
		return event.Verdict{Effect: event.Deny, Message: "eval response failed (fail closed)"}
	}
	msg := resp.Message
	if resp.RuleName != "" {
		msg = fmt.Sprintf("rule %q: %s", resp.RuleName, msg)
	}
	return event.Verdict{Effect: resp.Effect, RuleName: resp.RuleName, Message: msg}
}
