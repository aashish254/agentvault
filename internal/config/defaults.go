package config

import (
	"os"
	"path/filepath"
	"time"
)

// DefaultPolicy returns the secure-by-default template written by
// `agentvault init`. Credentials are denied, destructive shell is denied,
// the working directory is free, and anything network-ish or irreversible
// asks first.
func DefaultPolicy() *Policy {
	home, _ := os.UserHomeDir()
	return &Policy{
		Version: 1,
		Agent:   AgentCfg{Name: "unknown"},
		Defaults: DefaultsCfg{
			Action:          EffectDeny,
			ApprovalTimeout: 60 * time.Second,
		},
		Budgets: BudgetsCfg{MaxActionsPerMinute: 120},
		Rules: []Rule{
			{
				Name: "protect-credentials",
				Match: Match{
					Action: []ActionType{ActionFSRead, ActionFSWrite, ActionFSDelete},
					Path: []string{
						filepath.Join(home, ".ssh", "**"),
						filepath.Join(home, ".aws", "**"),
						filepath.Join(home, ".config", "gcloud", "**"),
					},
				},
				Effect:  EffectDeny,
				Message: "Credential paths are off-limits to agents.",
			},
			{
				Name: "block-destructive-shell",
				Match: Match{
					Action: []ActionType{ActionShell},
					CEL:    `event.cmd in ["rm","dd","mkfs","shutdown","reboot"] || event.argv.exists(a, a.startsWith("-rf"))`,
				},
				Effect:  EffectDeny,
				Message: "Destructive shell commands are blocked.",
			},
			{
				Name: "workdir-is-free",
				Match: Match{
					Action: []ActionType{ActionFSRead, ActionFSWrite},
					Path:   []string{"./**"},
				},
				Effect: EffectAllow,
			},
			{
				Name: "git-push-ask",
				Match: Match{
					Action: []ActionType{ActionShell},
					CEL:    `event.cmd == "git" && event.argv.size() > 1 && event.argv[1] == "push"`,
				},
				Effect:  EffectRequireApproval,
				Message: "Pushing code requires your approval.",
			},
		},
		Approvals: ApprovalsCfg{
			Timeout: 60 * time.Second,
			Channels: ChannelsCfg{
				TTY: TTYCfg{Enabled: true},
			},
		},
		Shims: ShimsCfg{
			Binaries: []string{"rm", "curl", "wget", "ssh", "scp", "git", "npm", "npx", "pip", "brew", "dd"},
		},
		Egress: EgressCfg{
			Listen:  "127.0.0.1:0",
			Default: EffectDeny,
		},
		Audit: AuditCfg{
			Path:          filepath.Join(home, ".agentvault", "audit.db"),
			RetentionDays: 90,
			SignOnClose:   true,
		},
	}
}
