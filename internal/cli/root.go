// Package cli wires every agentvault subcommand via cobra.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes (contract from SPEC §4.1).
const (
	ExitOK            = 0
	ExitUserAbort     = 1
	ExitPolicyFailure = 2
	ExitTampered      = 3
	ExitDenied        = 126
	ExitCheckFailed   = 77
)

var (
	flagConfig  string
	flagVerbose bool
	flagNoColor bool
)

// Execute runs the root command and returns the process exit code.
func Execute() int {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "agentvault:", err)
		return ExitPolicyFailure
	}
	return ExitOK
}

// newRootCmd builds a fresh command tree. Kept separate from Execute so
// tests can drive the CLI in-process with custom args and output buffers.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "agentvault",
		Short: "AgentVault — a permission firewall for AI agents",
		Long: `AgentVault wraps AI agents (OpenCode, OpenClaw, anything) in a runtime
permission firewall: YAML rules for what they may touch, one-tap
approvals for dangerous actions, and a tamper-evident log of
everything they did.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&flagConfig, "config", "c", "agentvault.yaml", "path to policy file")
	root.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "verbose logging to stderr")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable colored output")

	root.AddCommand(
		newPolicyCmd(),
		// run, log, init, verify, approve, daemon, __shim land in Weeks 2–6.
	)
	return root
}
