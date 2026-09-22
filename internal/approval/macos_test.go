package approval

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

func macosTestRequest() Request {
	return Request{
		Event: event.Event{
			ID: "ev-1", Action: event.ActionShell, Raw: "git push origin HEAD",
			Cmd: "git", Cwd: "/work",
		},
		RuleName:  "git-push-ask",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(60 * time.Second),
	}
}

func TestMacOSDialogAllowOnce(t *testing.T) {
	var gotScript string
	ch := newMacOSWith(func(_ context.Context, script string) (string, error) {
		gotScript = script
		return "button returned:Allow Once, gave up:false", nil
	})
	respCh, err := ch.Ask(context.Background(), macosTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-respCh:
		if !r.Allow || r.AllowRule {
			t.Fatalf("want allow-once, got %+v", r)
		}
		if r.By != "macos-dialog" {
			t.Fatalf("By = %q", r.By)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no response")
	}
	// The dialog must carry the context a human needs to decide.
	for _, want := range []string{"git-push-ask", "git push origin HEAD", "/work", "Deny", "Always Allow", "giving up after"} {
		if !strings.Contains(gotScript, want) {
			t.Errorf("dialog script missing %q:\n%s", want, gotScript)
		}
	}
	// Shell actions must spell out the stakes.
	if !strings.Contains(gotScript, "full permissions") {
		t.Error("dialog script missing risk hint for shell actions")
	}
}

func TestMacOSDialogAlwaysAllow(t *testing.T) {
	ch := newMacOSWith(func(context.Context, string) (string, error) {
		return "button returned:Always Allow", nil
	})
	respCh, _ := ch.Ask(context.Background(), macosTestRequest())
	r := <-respCh
	if !r.Allow || !r.AllowRule {
		t.Fatalf("want allow+memoize, got %+v", r)
	}
}

func TestMacOSDialogDenyAndDismiss(t *testing.T) {
	ch := newMacOSWith(func(context.Context, string) (string, error) {
		return "button returned:Deny", nil
	})
	respCh, _ := ch.Ask(context.Background(), macosTestRequest())
	if r := <-respCh; r.Allow {
		t.Fatal("Deny button must deny")
	}

	// Error (user pressed cancel / osascript missing): NO response — the
	// daemon's timeout must be what denies (fail closed).
	silent := newMacOSWith(func(context.Context, string) (string, error) {
		return "", errors.New("User canceled.")
	})
	silentCh, _ := silent.Ask(context.Background(), macosTestRequest())
	select {
	case r := <-silentCh:
		t.Fatalf("dismissed dialog must not produce a response, got %+v", r)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestMacOSAppleQuoteEscapes(t *testing.T) {
	got := appleQuote("say \"hi\"\nnew\\line")
	if !strings.Contains(got, `\"hi\"`) || !strings.Contains(got, `" & return & "`) || !strings.Contains(got, `\\`) {
		t.Fatalf("bad escaping: %s", got)
	}
}

func TestMacOSRiskHints(t *testing.T) {
	cases := []struct {
		action event.ActionType
		want   string
	}{
		{event.ActionShell, "full permissions"},
		{event.ActionNetEgress, "SEND data"},
		{event.ActionFSWrite, "unrecoverable"},
		{event.ActionFSRead, "reads a file"},
		{event.ActionMCPTool, "external tool"},
	}
	for _, c := range cases {
		r := macosTestRequest()
		r.Event.Action = c.action
		if hint := riskHint(r); !strings.Contains(hint, c.want) {
			t.Errorf("%s: hint %q missing %q", c.action, hint, c.want)
		}
	}
}
