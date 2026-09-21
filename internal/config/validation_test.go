package config

import (
	"testing"
	"time"
)

func loadErr(t *testing.T, y string) {
	t.Helper()
	if _, _, err := Load(writeTemp(t, y)); err == nil {
		t.Fatal("expected load error, got nil")
	}
}

func TestValidateBadEffect(t *testing.T) {
	loadErr(t, `
version: 1
defaults: {action: deny}
rules:
  - name: r
    match: {action: [fs.read]}
    effect: yolo
`)
}

func TestValidateBadDefaultAction(t *testing.T) {
	loadErr(t, "version: 1\ndefaults: {action: maybe}\nrules: []\n")
}

func TestValidateBadActionType(t *testing.T) {
	loadErr(t, `
version: 1
defaults: {action: deny}
rules:
  - name: r
    match: {action: [disk.format]}
    effect: deny
`)
}

func TestValidateMCPServerNeedsCommand(t *testing.T) {
	loadErr(t, `
version: 1
defaults: {action: deny}
rules:
  - name: r
    match: {action: [fs.read]}
    effect: deny
mcp_servers:
  - name: fs
`)
}

func TestValidateMCPToolPolicyBadEffect(t *testing.T) {
	loadErr(t, `
version: 1
defaults: {action: deny}
rules:
  - name: r
    match: {action: [fs.read]}
    effect: deny
mcp_servers:
  - name: fs
    command: [npx, server]
    tool_policies:
      - tool: delete_file
        effect: sometimes
`)
}

func TestValidateBadEgressDefault(t *testing.T) {
	loadErr(t, `
version: 1
defaults: {action: deny}
rules:
  - name: r
    match: {action: [fs.read]}
    effect: deny
egress:
  default: shrug
`)
}

func TestTelegramEnabledRequiresEnvVars(t *testing.T) {
	y := `
version: 1
defaults: {action: deny}
rules:
  - name: r
    match: {action: [fs.read]}
    effect: deny
approvals:
  channels:
    telegram:
      enabled: true
      bot_token_env: AV_TEST_TOK
      chat_id_env: AV_TEST_CHAT
`
	loadErr(t, y) // env not set → must fail
	t.Setenv("AV_TEST_TOK", "x")
	loadErr(t, y) // one set, one missing → must still fail
	t.Setenv("AV_TEST_CHAT", "y")
	if _, _, err := Load(writeTemp(t, y)); err != nil {
		t.Fatalf("env set, should load: %v", err)
	}
}

func TestApprovalTimeoutDefaults(t *testing.T) {
	pol, _, err := Load(writeTemp(t, minimalValid))
	if err != nil {
		t.Fatal(err)
	}
	if pol.Defaults.ApprovalTimeout != 60*time.Second {
		t.Fatalf("default approval_timeout = %v", pol.Defaults.ApprovalTimeout)
	}
	if pol.Approvals.Timeout != 60*time.Second {
		t.Fatalf("approvals.timeout should inherit defaults, got %v", pol.Approvals.Timeout)
	}
}

func TestBadDurationIsFatal(t *testing.T) {
	loadErr(t, "version: 1\ndefaults: {action: deny, approval_timeout: forever}\nrules: []\n")
}

func TestMissingFileError(t *testing.T) {
	if _, _, err := Load("/nonexistent/agentvault.yaml"); err == nil {
		t.Fatal("expected read error")
	}
}

func TestEffectValid(t *testing.T) {
	for _, e := range []Effect{EffectAllow, EffectDeny, EffectRequireApproval} {
		if !e.Valid() {
			t.Fatalf("%s should be valid", e)
		}
	}
	if Effect("").Valid() || Effect("MAYBE").Valid() {
		t.Fatal("invalid effects must not validate")
	}
}
