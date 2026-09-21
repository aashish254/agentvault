//go:build darwin

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aashish/agentvault/internal/event"
)

// sandboxPolicy: shim rm/ls, sandbox on, workdir writes allowed, ~/.ssh denied.
const sandboxPolicyTmpl = `
version: 1
defaults: {action: deny}
rules:
  - name: block-rm
    match: {action: [shell.exec], cel: 'event.cmd == "rm"'}
    effect: deny
  - name: allow-ls
    match: {action: [shell.exec], cel: 'event.cmd == "ls"'}
    effect: allow
  - name: workdir-writes
    match: {action: [fs.write], path: ["WORKDIR_GLOB"]}
    effect: allow
shims: {binaries: [rm, ls]}
sandbox: {enabled: true}
audit: {path: "AUDIT_PATH_PLACEHOLDER"}
`

func TestKernelSandboxBlocksDirectSyscall(t *testing.T) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec unavailable")
	}
	h := New(t, "")
	policy := strings.ReplaceAll(sandboxPolicyTmpl, "AUDIT_PATH_PLACEHOLDER", h.VaultDir+"/audit.db")
	policy = strings.ReplaceAll(policy, "WORKDIR_GLOB", h.WorkDir+"/**")
	writePolicyFile(t, h.Policy, policy)

	// Victims: a file in workdir (shim must block rm) and a file in a
	// directory that is NOT writable under the sandbox (kernel must refuse
	// even a direct /bin/rm). Note: t.TempDir() is unusable here — macOS
	// per-user temp (/var/folders/...) is writable by design, so we use a
	// fresh dir directly under $HOME (home root is not writable).
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(home, "av-sandbox-test-"+event.NewID()[:8])
	victim := filepath.Join(outside, "victim.txt")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outside) })
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	inside := h.WorkDir + "/inside.txt"
	if err := os.WriteFile(inside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	script := `
echo "agent-start"
# Attempt 1: shimmed rm (policy denies) — blocked by the shim layer.
rm -f "` + inside + `" 2>&1
echo "shim-rm-exit=$?"
# Attempt 2: DIRECT binary call, bypassing the shim — the KERNEL must stop it.
/bin/rm -f "` + victim + `" 2>&1
echo "direct-rm-exit=$?"
# Sanity: ls works (shim allowed) and sandbox didn't break the system.
ls /tmp >/dev/null && echo "ls-ok"
echo "agent-end"
`
	scriptPath := writeScript(t, h, script)
	out, code := h.Run("bash", scriptPath)

	if !strings.Contains(out, "kernel sandbox: ON") {
		t.Fatalf("sandbox must report ON:\n%s", out)
	}
	if !strings.Contains(out, "shim-rm-exit=126") {
		t.Fatalf("shimmed rm must be denied (126):\n%s", out)
	}
	if strings.Contains(out, "direct-rm-exit=0") {
		t.Fatalf("DIRECT /bin/rm SUCCEEDED — sandbox did not block it:\n%s", out)
	}
	// The file outside the workdir must still exist.
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("KERNEL FAILED: victim was deleted via /bin/rm bypass:\n%s", out)
	}
	if !strings.Contains(out, "ls-ok") {
		t.Fatalf("ls must work under sandbox:\n%s", out)
	}
	if code != 0 {
		t.Fatalf("agent exit = %d\n%s", code, out)
	}
}

func TestSandboxNetworkRestriction(t *testing.T) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec unavailable")
	}
	h := New(t, "")
	// Egress on: policy denies all; proxy would allow nothing either.
	policy := `
version: 1
defaults: {action: deny}
rules:
  - name: allow-curl
    match: {action: [shell.exec], cel: 'event.cmd == "curl"'}
    effect: allow
shims: {binaries: [curl]}
sandbox: {enabled: true}
egress:
  listen: "127.0.0.1:0"
  default: deny
audit: {path: "` + h.VaultDir + `/audit.db"}
`
	writePolicyFile(t, h.Policy, policy)

	// curl to a NON-proxy bypass: talk raw TCP to a listening socket.
	// The sandbox's deny network-outbound (except loopback+proxy) should
	// block even a direct connection that ignores HTTP_PROXY.
	script := `
echo "agent-start"
# Direct TCP to a non-proxy address — ignores proxy env entirely.
nc -z -w 3 1.1.1.1 443 2>&1
echo "nc-exit=$?"
echo "agent-end"
`
	scriptPath := writeScript(t, h, script)
	out, _ := h.Run("bash", scriptPath)
	// nc to an external IP must NOT succeed (sandbox denies it).
	// It fails with a non-zero exit or an operation-not-permitted error.
	if strings.Contains(out, "nc-exit=0") {
		t.Fatalf("network-outbound NOT restricted by kernel:\n%s", out)
	}
	if !strings.Contains(out, "kernel sandbox: ON") {
		t.Fatalf("sandbox must be on:\n%s", out)
	}
}
