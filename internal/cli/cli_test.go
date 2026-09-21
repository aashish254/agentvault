package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCLI executes the command tree in-process and captures output.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agentvault.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeFixture(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ev.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const cliValid = `
version: 1
defaults: {action: deny}
rules:
  - name: block-rm
    match:
      action: [shell.exec]
      cel: 'event.cmd == "rm"'
    effect: deny
    message: "no rm"
  - name: ask-push
    match:
      action: [shell.exec]
      cel: 'event.cmd == "git"'
    effect: require_approval
`

func TestPolicyCheckValid(t *testing.T) {
	stdout, _, err := runCLI(t, "-c", writePolicy(t, cliValid), "policy", "check")
	if err != nil {
		t.Fatalf("check failed: %v", err)
	}
	if !strings.Contains(stdout, "policy OK: 2 rules") {
		t.Fatalf("missing summary: %q", stdout)
	}
	if !strings.Contains(stdout, "block-rm") || !strings.Contains(stdout, "ask-push") {
		t.Fatalf("missing per-rule lines: %q", stdout)
	}
}

func TestPolicyCheckInvalidConfig(t *testing.T) {
	bad := writePolicy(t, "version: 9\n")
	if _, _, err := runCLI(t, "-c", bad, "policy", "check"); err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestPolicyCheckCELCompileError(t *testing.T) {
	bad := writePolicy(t, `
version: 1
defaults: {action: deny}
rules:
  - name: broken
    match: {action: [shell.exec], cel: "event.cmd ==="}
    effect: deny
`)
	if _, _, err := runCLI(t, "-c", bad, "policy", "check"); err == nil {
		t.Fatal("expected CEL compile error")
	}
}

func TestPolicyCheckShadowWarning(t *testing.T) {
	shadowed := writePolicy(t, `
version: 1
defaults: {action: deny}
rules:
  - name: first
    match: {action: [shell.exec]}
    effect: allow
  - name: second
    match: {action: [shell.exec]}
    effect: deny
`)
	_, stderr, err := runCLI(t, "-c", shadowed, "policy", "check")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "shadowed") || !strings.Contains(stderr, "second") {
		t.Fatalf("missing shadow warning: %q", stderr)
	}
}

func TestPolicyTestEndToEnd(t *testing.T) {
	fixture := writeFixture(t, `{"action":"shell.exec","cmd":"rm","argv":["rm","-rf","/"],"cwd":"/tmp"}`)
	stdout, _, err := runCLI(t, "-c", writePolicy(t, cliValid), "policy", "test", fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "verdict=deny rule=block-rm") {
		t.Fatalf("unexpected output: %q", stdout)
	}
	if !strings.Contains(stdout, "message: no rm") {
		t.Fatalf("missing rule message: %q", stdout)
	}
}

func TestPolicyTestDefaultRuleLabel(t *testing.T) {
	fixture := writeFixture(t, `{"action":"fs.read","path":"/etc/hosts","cwd":"/tmp"}`)
	stdout, _, err := runCLI(t, "-c", writePolicy(t, cliValid), "policy", "test", fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "rule=(default)") {
		t.Fatalf("default verdict must be labeled (default): %q", stdout)
	}
}

func TestPolicyTestBadFixture(t *testing.T) {
	fixture := writeFixture(t, `{not json`)
	if _, _, err := runCLI(t, "-c", writePolicy(t, cliValid), "policy", "test", fixture); err == nil {
		t.Fatal("expected fixture parse error")
	}
}

func TestPolicyTestMissingFixture(t *testing.T) {
	if _, _, err := runCLI(t, "-c", writePolicy(t, cliValid), "policy", "test", "/nope.json"); err == nil {
		t.Fatal("expected read error")
	}
}
