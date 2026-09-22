//go:build !windows

// Package redteam is AgentVault's public attack battery.
//
// Each subtest scripts an adversarial "AI agent" and runs it against the
// real agentvault binary, asserting that the expected enforcement layer
// stops (or honestly fails to stop) the attack. This is the reproducible
// evidence behind the claims in README.md and docs/COMPARISON.md —
// anyone can run it:
//
//	go test -v ./test/redteam/
//	make redteam        # also regenerates docs/redteam/RESULTS.md
//
// Outcomes are reported as BLOCKED (prevented), DETECTED (not prevented,
// but provably recorded), KNOWN GAP (documented limitation — see
// SECURITY.md), or SKIPPED (platform does not apply).
package redteam

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aashish/agentvault/test/e2e"
)

type outcome string

const (
	outBlocked  outcome = "BLOCKED"
	outDetected outcome = "DETECTED"
	outGap      outcome = "KNOWN GAP"
	outSkipped  outcome = "SKIPPED"
)

type row struct {
	id        string
	attack    string
	simulates string
	layer     string
	outcome   outcome
	detail    string
}

var results []row

func record(r row) { results = append(results, r) }

// --- policies -----------------------------------------------------------

// basePolicy is a realistic developer default: destructive commands
// denied, git requires approval, everything else denied by default.
const basePolicy = `
version: 1
defaults: {action: deny}
approvals: {timeout: 2s}
rules:
  - name: block-destructive
    match: {action: [shell.exec], cel: 'event.cmd in ["rm", "dd", "mkfs", "shutdown", "reboot"]'}
    effect: deny
    message: "Destructive shell commands are blocked."
  - name: allow-ls
    match: {action: [shell.exec], cel: 'event.cmd == "ls"'}
    effect: allow
  - name: git-push-ask
    match: {action: [shell.exec], cel: 'event.cmd == "git"'}
    effect: require_approval
shims: {binaries: [rm, dd, git, ls]}
audit: {path: "%s", sign_on_close: true}
`

const egressPolicy = `
version: 1
defaults: {action: deny}
approvals: {timeout: 2s}
rules:
  - name: allow-curl
    match: {action: [shell.exec], cel: 'event.cmd == "curl"'}
    effect: allow
shims: {binaries: [curl]}
egress:
  listen: "127.0.0.1:0"
  default: deny
audit: {path: "%s", sign_on_close: true}
`

// sandboxPolicyTmpl: workdir glob, extra rules, sandbox line (darwin
// only — honest degradation elsewhere), audit path.
const sandboxPolicyTmpl = `
version: 1
defaults: {action: deny}
approvals: {timeout: 2s}
rules:
  - name: block-destructive
    match: {action: [shell.exec], cel: 'event.cmd in ["rm", "dd", "mkfs"]'}
    effect: deny
  - name: allow-ls
    match: {action: [shell.exec], cel: 'event.cmd == "ls"'}
    effect: allow
  - name: workdir-writes
    match: {action: [fs.write], path: ["%s"]}
    effect: allow
%s
shims: {binaries: [rm, ls]}
%s
audit: {path: "%s", sign_on_close: true}
`

const protectSecretsRule = `
  - name: protect-secrets
    match: {action: [fs.read, fs.write, fs.delete], path: ["%s"]}
    effect: deny
    message: "Credential paths are off-limits to agents."
`

// sandboxEgressPolicy: sandbox on + egress default-deny, so the kernel
// profile also restricts network-outbound. %s = audit path.
const sandboxEgressPolicy = `
version: 1
defaults: {action: deny}
approvals: {timeout: 2s}
rules:
  - name: allow-ls
    match: {action: [shell.exec], cel: 'event.cmd == "ls"'}
    effect: allow
shims: {binaries: [ls]}
sandbox: {enabled: true}
egress:
  listen: "127.0.0.1:0"
  default: deny
audit: {path: "%s", sign_on_close: true}
`

// --- helpers ------------------------------------------------------------

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runScript(t *testing.T, h *e2e.Harness, script string) (string, int) {
	t.Helper()
	p := filepath.Join(h.WorkDir, "agent.sh")
	writeFile(t, p, script)
	return h.Run("bash", p)
}

// outsideDir returns a directory the macOS sandbox must treat as
// off-limits. macOS per-user temp (/var/folders/...) is writable by
// design, so — as in test/e2e — we use a fresh dir under $HOME.
func outsideDir(t *testing.T, name string) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(home, "av-redteam-"+name+"-"+fmt.Sprint(time.Now().UnixNano()))
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func sandboxAvailable() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := exec.LookPath("sandbox-exec")
	return err == nil
}

func newSandboxHarness(t *testing.T, extraRules string) *e2e.Harness {
	t.Helper()
	h := e2e.New(t, "")
	sandboxLine := ""
	if runtime.GOOS == "darwin" {
		sandboxLine = "sandbox: {enabled: true}"
	}
	policy := fmt.Sprintf(sandboxPolicyTmpl, h.WorkDir+"/**", extraRules, sandboxLine, h.VaultDir+"/audit.db")
	writeFile(t, h.Policy, policy)
	return h
}
