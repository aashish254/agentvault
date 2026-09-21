package cli

import (
	"encoding/json"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/aashish/agentvault/internal/audit"
	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/tui"
)

func newLogCmd() *cobra.Command {
	var (
		export  string
		session string
		verdict string
		action  string
		since   time.Duration
		limit   int
	)
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Inspect the audit log (TUI lands in Week 6; --export now)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if export == "" {
				// Interactive TUI (BubbleTea): live tail, filters, detail pane.
				pol, _, err := config.Load(flagConfig)
				if err != nil {
					return err
				}
				store, err := audit.Open(pol.Audit.Path)
				if err != nil {
					return err
				}
				defer func() { _ = store.Close() }()
				prog := tea.NewProgram(tui.NewModel(store), tea.WithAltScreen())
				_, err = prog.Run()
				return err
			}
			if export != "json" && export != "jsonl" {
				return fmt.Errorf("unsupported export format %q (json)", export)
			}
			pol, _, err := config.Load(flagConfig)
			if err != nil {
				return err
			}
			store, err := audit.Open(pol.Audit.Path)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()

			recs, err := store.Query(audit.QueryOpts{
				SessionID: session,
				Verdict:   verdict,
				Action:    action,
				Since:     since,
				Limit:     limit,
			})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			enc := json.NewEncoder(out)
			for _, r := range recs {
				if err := enc.Encode(r); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&export, "export", "", "export format: json (one record per line)")
	cmd.Flags().StringVar(&session, "session", "", "filter by session id")
	cmd.Flags().StringVar(&verdict, "verdict", "", "filter by verdict (allow|deny|require_approval)")
	cmd.Flags().StringVar(&action, "action", "", "filter by action (e.g. shell.exec)")
	cmd.Flags().DurationVar(&since, "since", 0, "only events newer than this (e.g. 24h)")
	cmd.Flags().IntVar(&limit, "limit", 0, "max records (0 = all)")
	return cmd
}
