//go:build !windows

package supervisor

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aashish/agentvault/internal/config"
	"github.com/aashish/agentvault/internal/event"
)

func testSupervisor(t *testing.T, policyYAML string) *Supervisor {
	t.Helper()
	t.Setenv("AGENTVAULT_HOME", t.TempDir())
	vault := os.Getenv("AGENTVAULT_HOME")
	full := policyYAML + "\naudit:\n  path: \"" + filepath.Join(vault, "audit.jsonl") + "\"\n"
	p := filepath.Join(vault, "agentvault.yaml")
	if err := os.WriteFile(p, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, _, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sup, err := New(pol)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Close() })
	return sup
}

const supPolicy = `
version: 1
defaults: {action: deny}
rules:
  - name: block-rm
    match:
      action: [shell.exec]
      cel: 'event.cmd == "rm"'
    effect: deny
  - name: allow-ls
    match:
      action: [shell.exec]
      cel: 'event.cmd == "ls"'
    effect: allow
  - name: ask-push
    match:
      action: [shell.exec]
      cel: 'event.cmd == "git"'
    effect: require_approval
shims:
  binaries: []
`

func TestEvaluateAllowDenyAskDegradation(t *testing.T) {
	sup := testSupervisor(t, supPolicy)
	mk := func(cmd string) event.Event {
		return event.Event{
			ID: event.NewID(), SessionID: sup.SessionID(),
			Source: event.SourceShim, Action: event.ActionShell,
			Cmd: cmd, Argv: []string{cmd}, Cwd: "/tmp",
		}
	}
	if v := sup.Evaluate(mk("ls")); v.Effect != event.Allow {
		t.Fatalf("ls: %s", v.Effect)
	}
	if v := sup.Evaluate(mk("rm")); v.Effect != event.Deny {
		t.Fatalf("rm: %s", v.Effect)
	}
	// require_approval with no approval daemon → fail-closed deny.
	v := sup.Evaluate(mk("git"))
	if v.Effect != event.Deny || !strings.Contains(v.Message, "fail-closed") {
		t.Fatalf("ask must degrade to deny with explanation, got %+v", v)
	}
	// Audit log must contain all three.
	data, err := os.ReadFile(filepath.Join(os.Getenv("AGENTVAULT_HOME"), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.TrimSpace(string(data)), "\n"); n != 2 {
		t.Fatalf("want 3 audit lines, got %d", n+1)
	}
}

func TestListenerRoundtrip(t *testing.T) {
	sup := testSupervisor(t, supPolicy)
	ln, err := startListener(sup.SessionID())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.close()
	go ln.serve(sup)

	var env []string
	for _, kv := range ln.envVars() {
		env = append(env, strings.SplitN(kv, "=", 2)[1])
	}
	conn, err := net.Dial("unix", env[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	req := event.EvalRequest{Type: "eval", Event: event.Event{
		ID: event.NewID(), Source: event.SourceShim,
		Action: event.ActionShell, Cmd: "rm", Argv: []string{"rm", "-rf", "/"}, Cwd: "/tmp",
	}}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatal(err)
	}
	var resp event.EvalResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Effect != event.Deny || resp.RuleName != "block-rm" {
		t.Fatalf("got %+v", resp)
	}
}

func TestListenerRejectsMalformed(t *testing.T) {
	sup := testSupervisor(t, supPolicy)
	ln, err := startListener(sup.SessionID())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.close()
	go ln.serve(sup)

	sock := strings.SplitN(ln.envVars()[0], "=", 2)[1]
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("garbage\n"))
	var resp event.EvalResponse
	if err := json.NewDecoder(conn).Decode(&resp); err == nil {
		t.Fatal("malformed request must get silence, not a verdict")
	}
}

func TestBuildChildEnv(t *testing.T) {
	t.Setenv("AGENTVAULT_HOME", "/vault-test")
	t.Setenv("AGENTVAULT_SESSION", "must-be-overridden")
	env := buildChildEnv(childEnv{
		ShimDir:   "/vault-test/shims",
		SessionID: "sess-1",
		IPCEnv:    []string{"AGENTVAULT_SOCK=/vault-test/run/sess-1.sock"},
	})
	joined := strings.Join(env, "\n")
	if !strings.HasPrefix(env[0], "PATH=/vault-test/shims"+string(os.PathListSeparator)) {
		t.Fatalf("shim dir must be first on PATH: %q", env[0])
	}
	if !strings.Contains(joined, "AGENTVAULT_SESSION=sess-1") {
		t.Fatal("session not set")
	}
	if strings.Count(joined, "AGENTVAULT_SESSION=") != 1 {
		t.Fatal("session must not be duplicated from parent env")
	}
	if !strings.Contains(joined, "AGENTVAULT_HOME=/vault-test") {
		t.Fatal("AGENTVAULT_HOME must pass through")
	}
	if !strings.Contains(joined, "AGENTVAULT_SOCK=/vault-test/run/sess-1.sock") {
		t.Fatal("socket env missing")
	}
}

func TestWaitChildExitCodes(t *testing.T) {
	cmd := spawnForTest(t, "sh", "-c", "exit 3")
	if code := waitChild(cmd); code != 3 {
		t.Fatalf("want 3, got %d", code)
	}
	cmd = spawnForTest(t, "sh", "-c", "exit 0")
	if code := waitChild(cmd); code != 0 {
		t.Fatalf("want 0, got %d", code)
	}
}

func spawnForTest(t *testing.T, argv ...string) *exec.Cmd {
	t.Helper()
	cmd, err := spawnChild(argv, childEnv{ShimDir: "/nonexistent", SessionID: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}
