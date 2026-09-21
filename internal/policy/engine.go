// Package policy compiles a config.Policy into a goroutine-safe Engine
// and evaluates InterceptedEvents against it. First match in document
// order wins; when no rule matches, defaults.action fires.
package policy

import (
	"fmt"
	"time"

	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/event"
)

// Engine evaluates events. Implementations must be goroutine-safe.
type Engine interface {
	Evaluate(e event.Event) event.Verdict
}

// compiledRule is a Rule with its CEL precompiled and matchers preprocessed.
type compiledRule struct {
	name    string
	effect  event.Effect
	message string
	match   config.Match
	cel     *celProgram // nil when the rule has no CEL expression
}

type engine struct {
	rules   []compiledRule
	def     event.Effect
	defName string // always "" — RuleName is empty when the default fires
}

// NewEngine compiles pol into an Engine. Any CEL compile error is fatal.
func NewEngine(pol *config.Policy) (Engine, error) {
	env, err := celEnv()
	if err != nil {
		return nil, fmt.Errorf("policy: CEL env: %w", err)
	}
	rules := make([]compiledRule, 0, len(pol.Rules))
	for _, r := range pol.Rules {
		cr := compiledRule{
			name:    r.Name,
			effect:  event.Effect(r.Effect),
			message: r.Message,
			match:   r.Match,
		}
		if r.Match.CEL != "" {
			cp, err := compileCEL(env, r.Name, r.Match.CEL)
			if err != nil {
				return nil, err
			}
			cr.cel = cp
		}
		rules = append(rules, cr)
	}
	return &engine{rules: rules, def: event.Effect(pol.Defaults.Action)}, nil
}

// Evaluate returns the verdict for e. Structural matchers run first
// (cheap), CEL last (short-circuits). First matching rule wins.
func (en *engine) Evaluate(e event.Event) event.Verdict {
	start := time.Now()
	for _, r := range en.rules {
		if matchRule(r, e) {
			return event.Verdict{
				Effect:     r.effect,
				RuleName:   r.name,
				Message:    r.message,
				EvalMicros: micros(start),
			}
		}
	}
	return event.Verdict{Effect: en.def, EvalMicros: micros(start)}
}

// micros reports elapsed time in microseconds, clamped to ≥1 so a
// recorded latency of 0 always means "not measured".
func micros(start time.Time) int64 {
	if us := time.Since(start).Microseconds(); us > 0 {
		return us
	}
	return 1
}

// matchRule ANDs all populated match fields; within a list, OR.
func matchRule(r compiledRule, e event.Event) bool {
	m := r.match
	if len(m.Action) > 0 && !actionIn(actionStrings(m.Action), string(e.Action)) {
		return false
	}
	if len(m.Tool) > 0 && !toolIn(m.Tool, e.Tool) {
		return false
	}
	if len(m.Path) > 0 {
		p := e.Path
		if p != "" {
			p = resolvePath(p, e.Cwd)
		}
		if !matchPath(m.Path, p, e.Cwd) {
			return false
		}
	}
	if len(m.Host) > 0 && !matchHost(m.Host, e.Host) {
		return false
	}
	if len(m.NotHost) > 0 && matchHost(m.NotHost, e.Host) {
		return false
	}
	if r.cel != nil {
		ok, err := r.cel.eval(e)
		if err != nil || !ok {
			return false // CEL errors never match (fail closed at eval level)
		}
	}
	return true
}

func actionStrings(as []config.ActionType) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = string(a)
	}
	return out
}
