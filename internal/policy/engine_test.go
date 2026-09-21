package policy

import (
	"path/filepath"
	"testing"

	"github.com/aashish/agentvault/internal/event"
)

// Engine-level edge cases beyond the corpus.

func TestEmptyRulesDefaultDeny(t *testing.T) {
	eng := engineFromYAML(t, "version: 1\ndefaults: {action: deny}\nrules: []\n")
	if v := eng.Evaluate(shellEvent("ls")); v.Effect != event.Deny || v.RuleName != "" {
		t.Fatalf("got %+v", v)
	}
}

func TestEmptyRulesDefaultAllow(t *testing.T) {
	y := `
version: 1
defaults: {action: allow}
rules:
  - name: something
    match: {action: [fs.read], path: ["/nowhere/**"]}
    effect: deny
`
	eng := engineFromYAML(t, y)
	if v := eng.Evaluate(shellEvent("anything")); v.Effect != event.Allow {
		t.Fatalf("default allow must fire, got %s", v.Effect)
	}
}

func TestRuleMessagePropagates(t *testing.T) {
	y := `
version: 1
defaults: {action: deny}
rules:
  - name: with-msg
    match: {action: [shell.exec]}
    effect: deny
    message: "explained to the user"
`
	eng := engineFromYAML(t, y)
	v := eng.Evaluate(shellEvent("whatever"))
	if v.Message != "explained to the user" {
		t.Fatalf("message = %q", v.Message)
	}
	// The spec policy's block-destructive-shell has no message — must be empty, not garbage.
	eng2 := engineFromYAML(t, specPolicy)
	if v := eng2.Evaluate(shellEvent("rm", "x")); v.Message != "" {
		t.Fatalf("rule without message must yield empty message, got %q", v.Message)
	}
}

func TestEventWithEmptyPathAgainstPathRule(t *testing.T) {
	// A shell.exec event has no path; a path-only rule must not match it.
	eng := engineFromYAML(t, specPolicy)
	v := eng.Evaluate(shellEvent("git", "status"))
	if v.RuleName == "workdir-is-free" {
		t.Fatal("path rule must not match an event with no path")
	}
}

func TestNotHostAloneMatchesEverythingElse(t *testing.T) {
	y := `
version: 1
defaults: {action: deny}
rules:
  - name: ask-all-but-one
    match:
      action: [net.egress]
      not_host: ["safe.example"]
    effect: require_approval
`
	eng := engineFromYAML(t, y)
	if v := eng.Evaluate(netEvent("safe.example", 443)); v.Effect != event.Deny {
		t.Fatalf("excluded host must fall to default, got %s", v.Effect)
	}
	if v := eng.Evaluate(netEvent("other.example", 443)); v.Effect != event.RequireApproval {
		t.Fatalf("non-excluded host must ask, got %s", v.Effect)
	}
}

func TestHostAndCELCombineAsAND(t *testing.T) {
	y := `
version: 1
defaults: {action: deny}
rules:
  - name: https-only
    match:
      action: [net.egress]
      host: ["api.example.com"]
      cel: "event.port == 443"
    effect: allow
`
	eng := engineFromYAML(t, y)
	if v := eng.Evaluate(netEvent("api.example.com", 443)); v.Effect != event.Allow {
		t.Fatal("host+port both match → allow")
	}
	if v := eng.Evaluate(netEvent("api.example.com", 80)); v.Effect != event.Deny {
		t.Fatal("port mismatch → default deny")
	}
	if v := eng.Evaluate(netEvent("other.example.com", 443)); v.Effect != event.Deny {
		t.Fatal("host mismatch → default deny")
	}
}

func TestSymlinkResolutionInPathMatch(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	if err := mkdirAll(real); err != nil {
		t.Fatal(err)
	}
	if err := symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	target := filepath.Join(link, "secret.txt")
	if err := writeFile(target, "x"); err != nil {
		t.Fatal(err)
	}
	y := `
version: 1
defaults: {action: deny}
rules:
  - name: real-tree-only
    match:
      action: [fs.read]
      path: ["` + real + `/**"]
    effect: allow
`
	eng := engineFromYAML(t, y)
	// Reading via the symlink must resolve to the real tree and match.
	if v := eng.Evaluate(fsEvent(event.ActionFSRead, target)); v.Effect != event.Allow {
		t.Fatalf("symlinked path must resolve and match, got %s", v.Effect)
	}
}

func TestNewEngineOnDefaultPolicy(t *testing.T) {
	// The shipped template must always compile — this is what users start with.
	if _, err := NewEngine(defaultPolicyForTest(t)); err != nil {
		t.Fatalf("default policy must compile: %v", err)
	}
}

func TestPortZeroEventAgainstEgressRule(t *testing.T) {
	// Degenerate event (no port) must not crash host rules.
	eng := engineFromYAML(t, specPolicy)
	v := eng.Evaluate(event.Event{Action: event.ActionNetEgress, Host: "x.example", Cwd: "/work"})
	if v.Effect != event.RequireApproval {
		t.Fatalf("got %s", v.Effect)
	}
}
