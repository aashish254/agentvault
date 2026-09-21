package cli

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/supervisor"
)

// newDaemonCmd runs the supervisor WITHOUT a child process: the IPC
// listener and approval daemon stay up so `agentvault approve` and
// long-running agents (started separately, pointing at this session)
// can resolve requests.
func newDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Run the approval daemon standalone (no child process)",
		Long: `Keeps the approval daemon + session IPC alive for headless or
always-on agents (e.g. OpenClaw). Resolve requests from another
terminal with 'agentvault approve list|allow|deny', or via Telegram.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, raw, err := config.Load(flagConfig)
			if err != nil {
				return err
			}
			sup, err := supervisor.New(pol, raw)
			if err != nil {
				return err
			}
			defer func() { _ = sup.Close() }()
			if err := sup.ServeOnly(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "agentvault: daemon up, session %s — ctrl-C to stop\n", sup.SessionID())

			sigCh := make(chan os.Signal, 2)
			signal.Notify(sigCh, os.Interrupt)
			<-sigCh
			fmt.Fprintln(cmd.ErrOrStderr(), "agentvault: daemon shutting down")
			return nil
		},
	}
}
