// Package config loads, expands, and validates agentvault.yaml policy files.
// Any load error is fatal to the supervisor (fail closed).
package config

import "time"

// Effect is the outcome vocabulary shared by config, engine, and audit.
type Effect string

const (
	EffectAllow           Effect = "allow"
	EffectDeny            Effect = "deny"
	EffectRequireApproval Effect = "require_approval"
)

// Valid reports whether e is one of the three known effects.
func (e Effect) Valid() bool {
	switch e {
	case EffectAllow, EffectDeny, EffectRequireApproval:
		return true
	}
	return false
}

// ActionType is the normalized action vocabulary across all channels.
type ActionType string

const (
	ActionFSRead    ActionType = "fs.read"
	ActionFSWrite   ActionType = "fs.write"
	ActionFSDelete  ActionType = "fs.delete"
	ActionShell     ActionType = "shell.exec"
	ActionNetEgress ActionType = "net.egress"
	ActionMCPTool   ActionType = "mcp.tool"
)

// Valid reports whether a is a known action type.
func (a ActionType) Valid() bool {
	switch a {
	case ActionFSRead, ActionFSWrite, ActionFSDelete,
		ActionShell, ActionNetEgress, ActionMCPTool:
		return true
	}
	return false
}

// Policy is the root of agentvault.yaml.
type Policy struct {
	Version    int            `yaml:"version"`
	Agent      AgentCfg       `yaml:"agent"`
	Defaults   DefaultsCfg    `yaml:"defaults"`
	Budgets    BudgetsCfg     `yaml:"budgets"`
	Rules      []Rule         `yaml:"rules"`
	Approvals  ApprovalsCfg   `yaml:"approvals"`
	MCPServers []MCPServerCfg `yaml:"mcp_servers"`
	Shims      ShimsCfg       `yaml:"shims"`
	Egress     EgressCfg      `yaml:"egress"`
	Audit      AuditCfg       `yaml:"audit"`
}

type AgentCfg struct {
	Name    string   `yaml:"name"`
	Command []string `yaml:"command"`
}

type DefaultsCfg struct {
	Action          Effect        `yaml:"action"`
	ApprovalTimeout time.Duration `yaml:"approval_timeout"`
}

type BudgetsCfg struct {
	DailySpendUSD       float64 `yaml:"daily_spend_usd"`
	MaxActionsPerMinute int     `yaml:"max_actions_per_minute"`
}

// Rule: first match in document order wins.
type Rule struct {
	Name    string  `yaml:"name"`
	Match   Match   `yaml:"match"`
	Effect  Effect  `yaml:"effect"`
	Message string  `yaml:"message,omitempty"`
}

// Match: all populated fields are ANDed; within a list, OR.
// CEL, when non-empty, must also evaluate true.
type Match struct {
	Action  []ActionType `yaml:"action,omitempty"`
	Path    []string     `yaml:"path,omitempty"`   // glob; ~ expanded; ** supported
	Host    []string     `yaml:"host,omitempty"`   // exact or *.suffix
	NotHost []string     `yaml:"not_host,omitempty"`
	Tool    []string     `yaml:"tool,omitempty"`   // MCP tool names
	CEL     string       `yaml:"cel,omitempty"`    // expression over `event`
}

// Empty reports whether m has no criteria set.
func (m Match) Empty() bool {
	return len(m.Action) == 0 && len(m.Path) == 0 && len(m.Host) == 0 &&
		len(m.NotHost) == 0 && len(m.Tool) == 0 && m.CEL == ""
}

type ApprovalsCfg struct {
	Timeout  time.Duration `yaml:"timeout"`
	Channels ChannelsCfg   `yaml:"channels"`
}

type ChannelsCfg struct {
	Telegram TelegramCfg `yaml:"telegram"`
	TTY      TTYCfg      `yaml:"tty"`
}

type TelegramCfg struct {
	Enabled     bool   `yaml:"enabled"`
	BotTokenEnv string `yaml:"bot_token_env"`
	ChatIDEnv   string `yaml:"chat_id_env"`
}

type TTYCfg struct {
	Enabled bool `yaml:"enabled"`
}

type MCPServerCfg struct {
	Name         string       `yaml:"name"`
	Command      []string     `yaml:"command"`
	ToolPolicies []ToolPolicy `yaml:"tool_policies,omitempty"`
}

type ToolPolicy struct {
	Tool   string `yaml:"tool"`
	Effect Effect `yaml:"effect"`
}

type ShimsCfg struct {
	Binaries []string `yaml:"binaries"`
}

type EgressCfg struct {
	Listen     string   `yaml:"listen"`
	Default    Effect   `yaml:"default"`
	AllowHosts []string `yaml:"allow_hosts"`
}

type AuditCfg struct {
	Path          string `yaml:"path"`
	RetentionDays int    `yaml:"retention_days"`
	SignOnClose   bool   `yaml:"sign_on_close"`
}
