package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/event"
	"github.com/aashish/agentvault/internal/policy"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Validate and test agentvault.yaml policies",
	}
	cmd.AddCommand(newPolicyCheckCmd(), newPolicyTestCmd())
	return cmd
}

func newPolicyCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Parse, compile, and lint the policy file",
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, _, err := config.Load(flagConfig)
			if err != nil {
				return err
			}
			if _, err := policy.NewEngine(pol); err != nil {
				return err
			}
			for i, r := range pol.Rules {
				fmt.Printf("  rule %-24s effect=%-16s ok\n", fmt.Sprintf("[%d] %s", i, r.Name), r.Effect)
			}
			warnShadowing(pol)
			fmt.Printf("policy OK: %d rules, default=%s\n", len(pol.Rules), pol.Defaults.Action)
			return nil
		},
	}
}

func newPolicyTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <fixture.json>",
		Short: "Evaluate a JSON-encoded event against the policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, _, err := config.Load(flagConfig)
			if err != nil {
				return err
			}
			eng, err := policy.NewEngine(pol)
			if err != nil {
				return err
			}
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read fixture: %w", err)
			}
			var e event.Event
			if err := json.Unmarshal(raw, &e); err != nil {
				return fmt.Errorf("fixture is not a valid event: %w", err)
			}
			v := eng.Evaluate(e)
			rule := v.RuleName
			if rule == "" {
				rule = "(default)"
			}
			fmt.Printf("verdict=%s rule=%s eval=%dµs\n", v.Effect, rule, v.EvalMicros)
			if v.Message != "" {
				fmt.Printf("message: %s\n", v.Message)
			}
			return nil
		},
	}
}

// warnShadowing prints a warning for rules that can never fire because an
// earlier same-action rule with an overlapping path/host set precedes them.
// v0.1 heuristic: exact duplicate criteria with a different effect.
func warnShadowing(pol *config.Policy) {
	for i, a := range pol.Rules {
		for j := i + 1; j < len(pol.Rules); j++ {
			b := pol.Rules[j]
			if sameCriteria(a.Match, b.Match) && a.Effect != b.Effect {
				fmt.Fprintf(os.Stderr,
					"warning: rule %q (rules[%d]) is shadowed by %q (rules[%d]) — same criteria, %s wins\n",
					b.Name, j, a.Name, i, a.Effect)
			}
		}
	}
}

func sameCriteria(a, b config.Match) bool {
	return fmt.Sprintf("%v", a.Action) == fmt.Sprintf("%v", b.Action) &&
		fmt.Sprintf("%v", a.Path) == fmt.Sprintf("%v", b.Path) &&
		fmt.Sprintf("%v", a.Host) == fmt.Sprintf("%v", b.Host) &&
		a.CEL == b.CEL
}
