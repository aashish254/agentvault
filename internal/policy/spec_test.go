package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aashish/agentvault/internal/event"
)

// The spec's own example policy (SPEC §3.1, trimmed to pure YAML/CEL).
const specPolicy = `
version: 1
defaults:
  action: deny
  approval_timeout: 60s
rules:
  - name: protect-credentials
    match:
      action: [fs.read, fs.write, fs.delete]
      path: ["~/.ssh/**", "~/.aws/**"]
    effect: deny
    message: "Credential paths are off-limits to agents."
  - name: block-destructive-shell
    match:
      action: [shell.exec]
      cel: 'event.cmd in ["rm","dd","mkfs"] || event.argv.exists(a, a.startsWith("-rf"))'
    effect: deny
  - name: workdir-is-free
    match:
      action: [fs.read, fs.write]
      path: ["/work/**"]
    effect: allow
  - name: net-egress-ask
    match:
      action: [net.egress]
      not_host: ["api.anthropic.com", "api.openai.com", "*.githubusercontent.com"]
    effect: require_approval
  - name: git-push-ask
    match:
      action: [shell.exec]
      cel: 'event.cmd == "git" && event.argv.size() > 1 && event.argv[1] == "push"'
    effect: require_approval
`

type verdictCase struct {
	name     string
	ev       event.Event
	want     event.Effect
	wantRule string // "" means the default fired
}

func runCases(t *testing.T, eng Engine, cases []verdictCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := eng.Evaluate(c.ev)
			if v.Effect != c.want {
				t.Fatalf("effect = %s, want %s", v.Effect, c.want)
			}
			if v.RuleName != c.wantRule {
				t.Fatalf("rule = %q, want %q", v.RuleName, c.wantRule)
			}
			if v.EvalMicros <= 0 {
				t.Fatal("EvalMicros not recorded")
			}
		})
	}
}

func TestSpecPolicy(t *testing.T) {
	eng := engineFromYAML(t, specPolicy)
	home, _ := os.UserHomeDir()
	runCases(t, eng, []verdictCase{
		{"rm -rf blocked", shellEvent("rm", "-rf", "/"), event.Deny, "block-destructive-shell"},
		{"dd blocked", shellEvent("dd", "if=/dev/zero", "of=/dev/sda"), event.Deny, "block-destructive-shell"},
		{"git push asks", shellEvent("git", "push", "origin", "main"), event.RequireApproval, "git-push-ask"},
		{"git status falls to default", shellEvent("git", "status"), event.Deny, ""},
		{"ls falls to default", shellEvent("ls", "-la"), event.Deny, ""},
		{"fs read in .ssh denied", fsEvent(event.ActionFSRead, filepath.Join(home, ".ssh", "id_rsa")), event.Deny, "protect-credentials"},
		{"fs read of ~/.ssh relative form denied", fsEvent(event.ActionFSRead, "~/.ssh/id_rsa"), event.Deny, "protect-credentials"},
		{"fs write in workdir allowed", fsEvent(event.ActionFSWrite, "/work/src/main.go"), event.Allow, "workdir-is-free"},
		{"fs delete in workdir falls to default deny", fsEvent(event.ActionFSDelete, "/work/src/main.go"), event.Deny, ""},
		{"egress to unknown asks", netEvent("evil.example", 443), event.RequireApproval, "net-egress-ask"},
		{"egress to exempt openai host falls to default deny", netEvent("api.openai.com", 443), event.Deny, ""},
		{"egress to gh subdomain exempt from ask rule", netEvent("raw.githubusercontent.com", 443), event.Deny, ""},
	})
}

func TestFirstMatchWins(t *testing.T) {
	y := `
version: 1
defaults: {action: deny}
rules:
  - name: first-allows
    match: {action: [shell.exec]}
    effect: allow
  - name: second-denies
    match: {action: [shell.exec]}
    effect: deny
`
	eng := engineFromYAML(t, y)
	v := eng.Evaluate(shellEvent("anything"))
	if v.Effect != event.Allow || v.RuleName != "first-allows" {
		t.Fatalf("first match must win, got %s/%s", v.Effect, v.RuleName)
	}
}

func TestCELCompileErrorIsFatal(t *testing.T) {
	y := `
version: 1
defaults: {action: deny}
rules:
  - name: broken
    match:
      action: [shell.exec]
      cel: 'event.cmd === "git"'
    effect: deny
`
	p := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, _, err := configLoad(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEngine(pol); err == nil {
		t.Fatal("expected CEL compile error")
	}
}

func TestCELErrorAtEvalNeverMatches(t *testing.T) {
	// Indexing argv out of range errors in CEL; the rule must not match.
	y := `
version: 1
defaults: {action: deny}
rules:
  - name: oob
    match:
      action: [shell.exec]
      cel: 'event.argv[9] == "x"'
    effect: allow
`
	eng := engineFromYAML(t, y)
	if v := eng.Evaluate(shellEvent("ls")); v.Effect != event.Deny {
		t.Fatalf("CEL runtime error must fall through to default, got %s", v.Effect)
	}
}

func TestMCPToolMatch(t *testing.T) {
	y := `
version: 1
defaults: {action: allow}
rules:
  - name: no-delete
    match:
      action: [mcp.tool]
      tool: [delete_file, remove_directory]
    effect: deny
`
	eng := engineFromYAML(t, y)
	runCases(t, eng, []verdictCase{
		{"delete_file denied", mcpEvent("fs", "delete_file"), event.Deny, "no-delete"},
		{"read_file allowed by default", mcpEvent("fs", "read_file"), event.Allow, ""},
	})
}
