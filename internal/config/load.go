package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Load reads path, expands ~ in path-like fields, and validates.
// It also returns the raw file bytes (hashed into sessions.policy_hash).
// Any error is fatal to the caller — fail closed.
func Load(path string) (p *Policy, raw []byte, err error) {
	// #nosec G304 -- reading the user-specified config path is the point.
	raw, err = os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // a typo'd key is a fatal error, not a silent ignore
	p = &Policy{}
	if err := dec.Decode(p); err != nil {
		return nil, nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	p.expand()
	if err := p.Validate(); err != nil {
		return nil, nil, err
	}
	return p, raw, nil
}

// expand resolves a leading ~/ in path-like fields. Environment variables
// are referenced by name (BotTokenEnv), never interpolated into secrets.
func (p *Policy) expand() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	tilde := func(s string) string {
		if s == "~" {
			return home
		}
		if strings.HasPrefix(s, "~/") {
			return filepath.Join(home, s[2:])
		}
		return s
	}
	for i := range p.Rules {
		for j := range p.Rules[i].Match.Path {
			p.Rules[i].Match.Path[j] = tilde(p.Rules[i].Match.Path[j])
		}
	}
	for j := range p.Sandbox.ExtraWritePaths {
		p.Sandbox.ExtraWritePaths[j] = tilde(p.Sandbox.ExtraWritePaths[j])
	}
	p.Audit.Path = tilde(p.Audit.Path)
}

// Validate enforces the fail-closed contract: anything ambiguous is an error.
func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("config: unsupported version %d (want 1)", p.Version)
	}
	if !p.Defaults.Action.Valid() {
		return fmt.Errorf("config: defaults.action %q is not allow|deny|require_approval", p.Defaults.Action)
	}
	if p.Defaults.ApprovalTimeout <= 0 {
		p.Defaults.ApprovalTimeout = 60 * time.Second
	}
	seen := map[string]int{}
	for i, r := range p.Rules {
		if r.Name == "" {
			return fmt.Errorf("config: rules[%d]: name is required", i)
		}
		if prev, dup := seen[r.Name]; dup {
			return fmt.Errorf("config: rules[%d]: duplicate rule name %q (first at rules[%d])", i, r.Name, prev)
		}
		seen[r.Name] = i
		if !r.Effect.Valid() {
			return fmt.Errorf("config: rule %q: effect %q is not allow|deny|require_approval", r.Name, r.Effect)
		}
		if r.Match.Empty() {
			return fmt.Errorf("config: rule %q: empty match block would match everything; use defaults.action instead", r.Name)
		}
		for _, a := range r.Match.Action {
			if !a.Valid() {
				return fmt.Errorf("config: rule %q: unknown action %q", r.Name, a)
			}
		}
	}
	if len(p.Rules) == 0 && p.Defaults.Action == EffectAllow {
		return fmt.Errorf("config: no rules and defaults.action=allow protects nothing; refusing to load")
	}
	for _, s := range p.MCPServers {
		if s.Name == "" || len(s.Command) == 0 {
			return fmt.Errorf("config: mcp_servers: each entry needs name and command")
		}
		for _, tp := range s.ToolPolicies {
			if !tp.Effect.Valid() {
				return fmt.Errorf("config: mcp_servers.%s: tool_policy %q has bad effect %q", s.Name, tp.Tool, tp.Effect)
			}
		}
	}
	if p.Egress.Default != "" && !p.Egress.Default.Valid() {
		return fmt.Errorf("config: egress.default %q is not allow|deny|require_approval", p.Egress.Default)
	}
	if tg := p.Approvals.Channels.Telegram; tg.Enabled {
		if tg.BotTokenEnv == "" || tg.ChatIDEnv == "" {
			return fmt.Errorf("config: approvals.telegram: bot_token_env and chat_id_env are required when enabled")
		}
		if os.Getenv(tg.BotTokenEnv) == "" || os.Getenv(tg.ChatIDEnv) == "" {
			return fmt.Errorf("config: approvals.telegram: env vars %s / %s are not set", tg.BotTokenEnv, tg.ChatIDEnv)
		}
	}
	if p.Approvals.Timeout <= 0 {
		p.Approvals.Timeout = p.Defaults.ApprovalTimeout
	}
	return nil
}
