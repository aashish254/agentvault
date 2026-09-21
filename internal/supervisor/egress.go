package supervisor

import (
	"time"

	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/event"
	"github.com/aashish/agentvault/internal/proxy/egress"
)

// withEgressRules layers the coarse egress section onto the rule list:
// allow_hosts and egress.default become synthetic rules appended AFTER
// user rules, so an explicit user deny still wins over an allowlisted
// host, and unmatched egress hits egress.default before the top default.
func withEgressRules(pol *config.Policy) *config.Policy {
	if pol.Egress.Listen == "" && len(pol.Egress.AllowHosts) == 0 && pol.Egress.Default == "" {
		return pol // egress section absent: no-op
	}
	cp := *pol
	rules := append([]config.Rule{}, pol.Rules...)
	if len(pol.Egress.AllowHosts) > 0 {
		rules = append(rules, config.Rule{
			Name: "egress.allow_hosts",
			Match: config.Match{
				Action: []config.ActionType{config.ActionNetEgress},
				Host:   pol.Egress.AllowHosts,
			},
			Effect: config.EffectAllow,
		})
	}
	if pol.Egress.Default != "" {
		rules = append(rules, config.Rule{
			Name:    "egress.default",
			Match:   config.Match{Action: []config.ActionType{config.ActionNetEgress}},
			Effect:  pol.Egress.Default,
			Message: "egress default policy",
		})
	}
	cp.Rules = rules
	return &cp
}

// startEgress launches the loopback proxy when the egress section is
// enabled (listen address configured). Returns the proxy URL for the
// child env, or "" when disabled.
func (s *Supervisor) startEgress() (string, error) {
	if s.cfg.Egress.Listen == "" {
		return "", nil
	}
	p := &egress.Proxy{Decide: s.decideEgress}
	if err := p.Start(); err != nil {
		return "", err
	}
	s.egressProxy = p
	return "http://" + p.Addr, nil
}

// decideEgress evaluates one net.egress event through the full pipeline
// (rules → approvals → audit), exactly like a shimmed command.
func (s *Supervisor) decideEgress(host string, port int) event.Verdict {
	return s.Evaluate(event.Event{
		ID:        event.NewID(),
		SessionID: s.session,
		Timestamp: time.Now().UTC(),
		Source:    event.SourceEgress,
		Action:    event.ActionNetEgress,
		Host:      host,
		Port:      port,
	})
}
