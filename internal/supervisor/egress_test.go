//go:build !windows

package supervisor

import (
	"testing"

	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/event"
	"github.com/aashish/agentvault/internal/policy"
)

func withEgressEngine(t *testing.T, pol *config.Policy) policy.Engine {
	t.Helper()
	eng, err := policy.NewEngine(withEgressRules(pol))
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func egressEv(host string) event.Event {
	return event.Event{
		ID: event.NewID(), Source: event.SourceEgress,
		Action: event.ActionNetEgress, Host: host, Port: 443, Cwd: "/work",
	}
}

func TestEgressRuleLayering(t *testing.T) {
	pol := &config.Policy{
		Version:  1,
		Defaults: config.DefaultsCfg{Action: config.EffectDeny},
		Rules: []config.Rule{{
			Name:   "user-deny-evil",
			Match:  config.Match{Action: []config.ActionType{config.ActionNetEgress}, Host: []string{"evil.example"}},
			Effect: config.EffectDeny,
		}},
		Egress: config.EgressCfg{
			Listen:     "127.0.0.1:0",
			Default:    config.EffectRequireApproval,
			AllowHosts: []string{"api.anthropic.com", "*.github.com"},
		},
	}
	eng := withEgressEngine(t, pol)

	// allow_hosts hit → allow via synthetic rule.
	if v := eng.Evaluate(egressEv("api.anthropic.com")); v.Effect != event.Allow || v.RuleName != "egress.allow_hosts" {
		t.Fatalf("allow_hosts: %+v", v)
	}
	// suffix allow_hosts.
	if v := eng.Evaluate(egressEv("gist.github.com")); v.Effect != event.Allow {
		t.Fatalf("suffix allow_hosts: %+v", v)
	}
	// unknown host → egress.default (require_approval).
	if v := eng.Evaluate(egressEv("random.example")); v.Effect != event.RequireApproval || v.RuleName != "egress.default" {
		t.Fatalf("egress.default: %+v", v)
	}
	// explicit user deny BEATS allow_hosts layering (rule order preserved).
	pol2 := *pol
	pol2.Egress.AllowHosts = []string{"evil.example"}
	eng2 := withEgressEngine(t, &pol2)
	if v := eng2.Evaluate(egressEv("evil.example")); v.Effect != event.Deny || v.RuleName != "user-deny-evil" {
		t.Fatalf("user rule must win over allow_hosts: %+v", v)
	}
}

func TestEgressAbsentIsNoOp(t *testing.T) {
	pol := &config.Policy{
		Version:  1,
		Defaults: config.DefaultsCfg{Action: config.EffectDeny},
		Rules: []config.Rule{{
			Name:   "r",
			Match:  config.Match{Action: []config.ActionType{config.ActionShell}},
			Effect: config.EffectAllow,
		}},
	}
	if withEgressRules(pol).Rules[0].Name != "r" || len(withEgressRules(pol).Rules) != 1 {
		t.Fatal("absent egress section must not inject rules")
	}
	// startEgress disabled → empty proxy URL.
	s := &Supervisor{cfg: pol}
	url, err := s.startEgress()
	if err != nil || url != "" {
		t.Fatalf("disabled egress: url=%q err=%v", url, err)
	}
}
