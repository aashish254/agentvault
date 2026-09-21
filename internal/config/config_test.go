package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agentvault.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimalValid = `
version: 1
defaults:
  action: deny
rules:
  - name: r1
    match:
      action: [fs.read]
      path: ["/tmp/**"]
    effect: allow
`

func TestLoadMinimalValid(t *testing.T) {
	pol, raw, err := Load(writeTemp(t, minimalValid))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if pol.Version != 1 || len(pol.Rules) != 1 || pol.Defaults.Action != EffectDeny {
		t.Fatalf("unexpected policy: %+v", pol)
	}
	if len(raw) == 0 {
		t.Fatal("raw bytes not returned")
	}
	if pol.Rules[0].Name != "r1" || pol.Rules[0].Effect != EffectAllow {
		t.Fatalf("bad rule: %+v", pol.Rules[0])
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	bad := minimalValid + "unknwon_key: true\n" // typo'd key must be fatal
	if _, _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestValidateRejectsBadVersion(t *testing.T) {
	bad := "version: 2\ndefaults: {action: deny}\nrules: []\n"
	if _, _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected version error")
	}
}

func TestValidateRejectsDuplicateRuleNames(t *testing.T) {
	bad := `
version: 1
defaults: {action: deny}
rules:
  - name: dup
    match: {action: [fs.read]}
    effect: allow
  - name: dup
    match: {action: [fs.write]}
    effect: deny
`
	if _, _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected duplicate-name error")
	}
}

func TestValidateRejectsEmptyMatch(t *testing.T) {
	bad := `
version: 1
defaults: {action: deny}
rules:
  - name: matches-everything
    match: {}
    effect: deny
`
	if _, _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected empty-match error")
	}
}

func TestValidateRejectsAllowAllDefault(t *testing.T) {
	bad := "version: 1\ndefaults: {action: allow}\nrules: []\n"
	if _, _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("expected no-protection error")
	}
}

func TestExpandTilde(t *testing.T) {
	home, _ := os.UserHomeDir()
	y := `
version: 1
defaults: {action: deny}
rules:
  - name: ssh
    match:
      action: [fs.read]
      path: ["~/.ssh/**"]
    effect: deny
audit:
  path: "~/audit.db"
`
	pol, _, err := Load(writeTemp(t, y))
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".ssh", "**")
	if pol.Rules[0].Match.Path[0] != want {
		t.Fatalf("tilde not expanded: got %q want %q", pol.Rules[0].Match.Path[0], want)
	}
	if pol.Audit.Path != filepath.Join(home, "audit.db") {
		t.Fatalf("audit path not expanded: %q", pol.Audit.Path)
	}
}

func TestDefaultPolicyIsValid(t *testing.T) {
	if err := DefaultPolicy().Validate(); err != nil {
		t.Fatalf("DefaultPolicy must validate: %v", err)
	}
}
