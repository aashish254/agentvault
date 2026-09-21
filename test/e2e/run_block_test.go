//go:build !windows

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

// e2ePolicy mirrors the Week-2 acceptance scenario: rm denied, ls
// allowed, git push requires approval (times out → deny in 2s here;
// the live approval path is covered by TestApprovalViaCLI).
const e2ePolicy = `
version: 1
defaults: {action: deny}
approvals:
  timeout: 2s
rules:
  - name: block-rm
    match:
      action: [shell.exec]
      cel: 'event.cmd == "rm"'
    effect: deny
    message: "rm is not allowed"
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
  binaries: [rm, ls, git]
audit:
  path: "AUDIT_PATH_PLACEHOLDER"
`

func TestRunBlocksDestructiveCommand(t *testing.T) {
	h := New(t, "") // policy written below (needs vault path first)
	policy := strings.ReplaceAll(e2ePolicy, "AUDIT_PATH_PLACEHOLDER", h.VaultDir+"/audit.db")
	writePolicyFile(t, h.Policy, policy)

	// The victim directory must survive the agent's rm -rf.
	victim := h.WorkDir + "/victim"
	mkdir(t, victim)

	out, code := h.Run("bash", fixturePath(t, "fakeagent.sh"))

	// 1. The agent ran to completion (supervisor doesn't kill the child).
	if code != 0 {
		t.Fatalf("agent process exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "agent-start") || !strings.Contains(out, "agent-end") {
		t.Fatalf("agent did not run to completion:\n%s", out)
	}

	// 2. Benign command passed through.
	if !strings.Contains(out, "ls-ran") {
		t.Fatalf("ls must have run:\n%s", out)
	}

	// 3. rm was denied with the rule name, exit 126, and the victim lives.
	if !strings.Contains(out, `denied by rule "block-rm"`) {
		t.Fatalf("deny message missing rule name:\n%s", out)
	}
	if !strings.Contains(out, "rm-exit=126") {
		t.Fatalf("rm must exit 126:\n%s", out)
	}
	if !exists(victim) {
		t.Fatal("victim directory was deleted — the block FAILED")
	}

	// 4. require_approval with nobody answering: timeout → deny.
	if !strings.Contains(out, "push-exit=126") || !strings.Contains(out, "timed out") {
		t.Fatalf("git push must time out into a deny:\n%s", out)
	}

	// 5. Audit log recorded all three attempts with correct verdicts.
	lines := strings.Split(strings.TrimSpace(h.AuditLog()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 audit records, got %d:\n%s", len(lines), h.AuditLog())
	}
	var verdicts []string
	for _, ln := range lines {
		var rec struct {
			Event struct {
				Cmd string `json:"cmd"`
			} `json:"event"`
			Verdict struct {
				Effect   string `json:"effect"`
				RuleName string `json:"rule_name"`
			} `json:"verdict"`
			Decision *struct {
				FinalEffect string `json:"final_effect"`
				TimedOut    bool   `json:"timed_out"`
			} `json:"decision"`
		}
		if err := json.Unmarshal([]byte(ln), &rec); err != nil {
			t.Fatalf("bad audit line: %v\n%s", err, ln)
		}
		v := rec.Event.Cmd + ":" + rec.Verdict.Effect + ":" + rec.Verdict.RuleName
		if rec.Decision != nil {
			v += ":" + rec.Decision.FinalEffect
		}
		verdicts = append(verdicts, v)
	}
	// The ask: verdict=require_approval, then decision=deny via timeout.
	want := []string{"ls:allow:allow-ls", "rm:deny:block-rm", "git:require_approval:ask-push:deny"}
	for i, w := range want {
		if verdicts[i] != w {
			t.Fatalf("audit[%d] = %q, want %q", i, verdicts[i], w)
		}
	}

	// 6. The hash chain verifies and the session signature is valid.
	vcode, vout := h.Verify()
	if vcode != 0 || !strings.Contains(vout, "OK") {
		t.Fatalf("verify = %d: %s", vcode, vout)
	}
}

func TestRunWithoutCommandIsUsageError(t *testing.T) {
	h := New(t, "version: 1\ndefaults: {action: deny}\nrules:\n  - {name: r, match: {action: [fs.read]}, effect: deny}\naudit: {path: \"x.jsonl\"}\n")
	out, code := h.Run()
	if code == 0 {
		t.Fatalf("run without command must fail, got 0\n%s", out)
	}
}
