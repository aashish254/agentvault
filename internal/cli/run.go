package cli

import (
	"github.com/spf13/cobra"

	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/supervisor"
)

func newRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run -- <command> [args...]",
		Short: "Run a command (e.g. an AI agent) inside the permission firewall",
		Long: `Run wraps a command with AgentVault's interception channels:
PATH shims for dangerous binaries, a local egress proxy, and wrapped
MCP servers. Every intercepted action is evaluated against the policy
and recorded in the tamper-evident audit log.`,
		Example: "  agentvault run -- opencode\n  agentvault run -- bash",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, raw, err := config.Load(resolveConfig())
			if err != nil {
				return err
			}
			sup, err := supervisor.New(pol, raw)
			if err != nil {
				return err
			}
			sup.Verbose = flagVerbose
			defer func() { _ = sup.Close() }()
			code, err := sup.Run(cmd.Context(), args)
			if err != nil {
				return err
			}
			// Propagate the child's exit code (SPEC §4.1).
			exitCode = code
			return nil
		},
	}
}

// exitCode is consulted by Execute when a subcommand wants to set the
// process exit code without returning an error.
var exitCode int
