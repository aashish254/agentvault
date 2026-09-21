// Package cli wires every agentvault subcommand via cobra.
package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/aashish/agentvault/internal/paths"
	"github.com/aashish/agentvault/internal/shim"
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
	exitCode = 0
	if err := newRootCmd().Execute(); err != nil {
		if err == errShimExit {
			return exitCode
		}
		fmt.Fprintln(os.Stderr, "agentvault:", err)
		return ExitPolicyFailure
	}
	return exitCode
}

// ShimDispatch implements the busybox pattern for unix shims: when the
// binary is invoked through a symlink whose name is not "agentvault",
// it behaves as that shimmed binary. Returns (handled, exitCode).
func ShimDispatch() (bool, int) {
	base := filepath.Base(os.Args[0])
	if base == "agentvault" || base == "agentvault.exe" || base == "main" {
		return false, 0
	}
	// Only treat argv[0] as a shim invocation if it names a real shim.
	if _, err := os.Lstat(filepath.Join(paths.Shims(), base)); err != nil {
		return false, 0
	}
	return true, shim.Handle(base, os.Args[1:])
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
		newRunCmd(),
		newShimCmd(),
		newVerifyCmd(),
		newLogCmd(),
		newApproveCmd(),
		newMCPCmd(),
		newInitCmd(),
		newDaemonCmd(),
	)
	return root
}
