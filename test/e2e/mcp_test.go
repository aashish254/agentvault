//go:build !windows

package e2e

import (
	"strings"
	"testing"
)

// Week-5 scenario: an agent whose filesystem access flows through the
// AgentVault MCP proxy. initialize passes through, delete_file on ~/.ssh
// is denied with -32000 naming the rule, read_file in the workdir reaches
// the real server, and both decisions land in the audit chain.
const mcpPolicy = `
version: 1
defaults: {action: deny}
rules:
  - name: protect-credentials
    match:
      action: [fs.read, fs.write, fs.delete]
      path: ["~/.ssh/**"]
    effect: deny
    message: "Credential paths are off-limits to agents."
  - name: workdir-is-free
    match:
      action: [fs.read, fs.write]
      path: ["/work/**"]
    effect: allow
shims:
  binaries: []
audit:
  path: "AUDIT_PATH_PLACEHOLDER"
`

func TestMCPProxyEndToEnd(t *testing.T) {
	h := New(t, "")
	policy := strings.ReplaceAll(mcpPolicy, "AUDIT_PATH_PLACEHOLDER", h.VaultDir+"/audit.db")
	writePolicyFile(t, h.Policy, policy)

	out, code := h.Run("bash", fixturePath(t, "mcpagent.sh"))
	if code != 0 {
		t.Fatalf("agent exit = %d\n%s", code, out)
	}
	if !strings.Contains(out, "agent-start") || !strings.Contains(out, "agent-end") {
		t.Fatalf("agent did not complete:\n%s", out)
	}

	// Responses are JSON-RPC: correlate by id, not position (the proxy
	// answers denies itself instantly; server responses arrive later).
	assertResp := func(id string, needles ...string) {
		t.Helper()
		for _, ln := range strings.Split(out, "\n") {
			if !strings.HasPrefix(ln, "resp") || !strings.Contains(ln, `"id":`+id) {
				continue
			}
			for _, n := range needles {
				if !strings.Contains(ln, n) {
					t.Fatalf("response id=%s missing %q:\n%s\nall output:\n%s", id, n, ln, out)
				}
			}
			return
		}
		t.Fatalf("no response with id=%s in:\n%s", id, out)
	}

	// 1. initialize passed through to the real server.
	assertResp("1", `"result"`)
	// 2. delete_file on ~/.ssh denied: -32000 naming the rule, server untouched.
	assertResp("2", `"error":{"code":-32000`, "protect-credentials")
	// 3. read_file in workdir allowed → real server answered.
	assertResp("3", `"result"`, "done")

	// 4. Audit: both decisions recorded with fs.* action mapping.
	log := h.AuditLog()
	if !strings.Contains(log, `"action":"fs.delete"`) || !strings.Contains(log, `"rule_name":"protect-credentials"`) {
		t.Fatalf("audit missing fs.delete deny:\n%s", log)
	}
	if !strings.Contains(log, `"action":"fs.read"`) {
		t.Fatalf("audit missing fs.read allow:\n%s", log)
	}
	if vcode, vout := h.Verify(); vcode != 0 {
		t.Fatalf("verify: %d\n%s", vcode, vout)
	}
}
