package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/aashish/agentvault/internal/event"
	"github.com/aashish/agentvault/internal/ipc"
)

func newApproveCmd() *cobra.Command {
	var session string
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "List and resolve pending approvals on a running session",
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "Show pending approval requests",
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := ipc.DialLatest(session, 2*time.Second)
			if err != nil {
				return err
			}
			defer func() { _ = conn.Close() }()
			if err := json.NewEncoder(conn).Encode(event.ApproveListRequest{Type: "approve.list", Token: ipc.EnvToken()}); err != nil {
				return err
			}
			var resp event.ApproveListResponse
			if err := json.NewDecoder(conn).Decode(&resp); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(resp.Pending) == 0 {
				fmt.Fprintln(out, "no pending approvals")
				return nil
			}
			for _, p := range resp.Pending {
				fmt.Fprintf(out, "%s  rule=%-20s %s  (expires %s)\n",
					p.EventID, p.RuleName, p.Summary, p.ExpiresAt.Format("15:04:05"))
			}
			return nil
		},
	}
	resolve := func(allow bool) *cobra.Command {
		verb := "deny"
		if allow {
			verb = "allow"
		}
		return &cobra.Command{
			Use:   verb + " <event-id-or-prefix>",
			Short: verb + " a pending approval request",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				conn, err := ipc.DialLatest(session, 2*time.Second)
				if err != nil {
					return err
				}
				defer func() { _ = conn.Close() }()
				if err := json.NewEncoder(conn).Encode(event.ApproveResolveRequest{
					Type: "approve.resolve", Token: ipc.EnvToken(), EventID: args[0], Allow: allow,
				}); err != nil {
					return err
				}
				var resp event.ApproveResolveResponse
				if err := json.NewDecoder(conn).Decode(&resp); err != nil {
					return err
				}
				if !resp.OK {
					return fmt.Errorf("%s", resp.Error)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", verb, resp.EventID)
				return nil
			},
		}
	}
	cmd.PersistentFlags().StringVar(&session, "session", "", "target session id or prefix (default: newest live session)")
	cmd.AddCommand(list, resolve(true), resolve(false))
	return cmd
}
