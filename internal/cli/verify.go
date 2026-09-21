package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aashish/agentvault/internal/audit"
	"github.com/aashish/agentvault/internal/config"
)

func newVerifyCmd() *cobra.Command {
	var sessionID string
	cmd := &cobra.Command{
		Use:   "verify [--session <id>]",
		Short: "Verify the audit log's hash chain and session signature",
		Long: `Recomputes the hash chain for a session and validates the
Ed25519 signature written when the session closed. Any tampering —
edited rows, deleted rows, reordered rows — is reported with the
first divergent sequence number. Exit code 3 means tampered.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, _, err := config.Load(flagConfig)
			if err != nil {
				return err
			}
			store, err := audit.Open(pol.Audit.Path)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()

			out := cmd.OutOrStdout()
			sessions := []string{sessionID}
			if sessionID == "" {
				if sessions, err = store.Sessions(); err != nil {
					return err
				}
				if len(sessions) == 0 {
					return fmt.Errorf("no sessions in %s", pol.Audit.Path)
				}
			}
			bad := 0
			for _, id := range sessions {
				err := store.Verify(id)
				switch {
				case err == nil:
					fmt.Fprintf(out, "OK       %s\n", id)
				case errors.Is(err, audit.ErrUnsealed):
					// Crashed/killed session: chain intact, just unsigned.
					// A warning, not a tamper alarm (exit stays 0).
					fmt.Fprintf(out, "UNSEALED %s: %v\n", id, err)
				default:
					fmt.Fprintf(out, "TAMPERED %s: %v\n", id, err)
					bad++
				}
			}
			if bad > 0 {
				exitCode = ExitTampered
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sessionID, "session", "", "verify only this session (default: all)")
	return cmd
}
