//go:build !windows

package e2e

import (
	"strings"
	"testing"
	"time"
)

// Week-4 scenario: agent hits a require_approval rule, a human approves
// from a SECOND terminal via `agentvault approve allow`, the action
// proceeds, and the audit log records the human decision.
const askPolicy = `
version: 1
defaults: {action: deny}
approvals:
  timeout: 15s
rules:
  - name: ask-push
    match:
      action: [shell.exec]
      cel: 'event.cmd == "git" && event.argv.size() > 1 && event.argv[1] == "push"'
    effect: require_approval
    message: "pushing code requires approval"
shims:
  binaries: [git]
audit:
  path: "AUDIT_PATH_PLACEHOLDER"
`

func TestApprovalViaCLI(t *testing.T) {
	h := New(t, "")
	policy := strings.ReplaceAll(askPolicy, "AUDIT_PATH_PLACEHOLDER", h.VaultDir+"/audit.db")
	writePolicyFile(t, h.Policy, policy)

	run := h.Start("bash", fixturePath(t, "askagent.sh"))

	// Poll `approve list` until the request shows up as pending.
	var eventID string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, err := h.Approve("list")
		if err == nil && strings.Contains(out, "git push origin main") {
			fields := strings.Fields(out)
			if len(fields) > 0 {
				eventID = fields[0]
			}
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if eventID == "" {
		out, _ := run.Wait(t)
		t.Fatalf("request never appeared in approve list; agent output:\n%s", out)
	}

	// Approve from "another terminal", using only a prefix like a human would.
	out, err := h.Approve("allow", eventID[:10])
	if err != nil || !strings.Contains(out, "allow") {
		t.Fatalf("approve allow failed: %v\n%s", err, out)
	}

	agentOut, code := run.Wait(t)
	if code != 0 {
		t.Fatalf("agent exit = %d\n%s", code, agentOut)
	}
	// git ran for real: no repo in WorkDir → exit 128, NOT the 126 deny.
	if !strings.Contains(agentOut, "push-exit=128") {
		t.Fatalf("approved push must execute (git fails 128 outside a repo):\n%s", agentOut)
	}
	if strings.Contains(agentOut, "denied") {
		t.Fatalf("approved action must not be denied:\n%s", agentOut)
	}

	// Audit must record the ask verdict + human allow decision.
	log := h.AuditLog()
	if !strings.Contains(log, `"require_approval"`) || !strings.Contains(log, `"final_effect":"allow"`) || !strings.Contains(log, `"approved_by":"cli"`) {
		t.Fatalf("audit missing approval decision:\n%s", log)
	}
	if vcode, vout := h.Verify(); vcode != 0 {
		t.Fatalf("verify after approval flow: %d\n%s", vcode, vout)
	}
}

func TestDenyViaCLI(t *testing.T) {
	h := New(t, "")
	policy := strings.ReplaceAll(askPolicy, "AUDIT_PATH_PLACEHOLDER", h.VaultDir+"/audit.db")
	writePolicyFile(t, h.Policy, policy)

	run := h.Start("bash", fixturePath(t, "askagent.sh"))

	var eventID string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, err := h.Approve("list")
		if err == nil && strings.Contains(out, "git push") {
			eventID = strings.Fields(out)[0]
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if eventID == "" {
		out, _ := run.Wait(t)
		t.Fatalf("request never appeared; agent output:\n%s", out)
	}

	if _, err := h.Approve("deny", eventID); err != nil {
		t.Fatalf("deny failed: %v", err)
	}
	agentOut, _ := run.Wait(t)
	if !strings.Contains(agentOut, "push-exit=126") || !strings.Contains(agentOut, "denied by cli") {
		t.Fatalf("denied push must exit 126 with attribution:\n%s", agentOut)
	}
	log := h.AuditLog()
	if !strings.Contains(log, `"final_effect":"deny"`) {
		t.Fatalf("audit missing deny decision:\n%s", log)
	}
}
