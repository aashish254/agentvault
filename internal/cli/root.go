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

var rootCmd = &cobra.Command{
	Use:   "agentvault",
	Short: "AgentVault — a permission firewall for AI agents",
	Long: `AgentVault wraps AI agents (OpenCode, OpenClaw, anything) in a runtime
permission firewall: YAML rules for what they may touch, one-tap
approvals for dangerous actions, and a tamper-evident log of
everything they did.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command and returns the process exit code.
func Execute() int {
	rootCmd.PersistentFlags().StringVarP(&flagConfig, "config", "c", "agentvault.yaml", "path to policy file")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "verbose logging to stderr")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "disable colored output")

	rootCmd.AddCommand(
		newPolicyCmd(),
		// run, log, init, verify, approve, daemon, __shim land in Weeks 2–6.
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "agentvault:", err)
		return ExitPolicyFailure
	}
	return ExitOK
}
