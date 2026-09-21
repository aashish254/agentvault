package approval

import (
	"context"
	"testing"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// fakeChannel records requests and plays back scripted responses.
type fakeChannel struct {
	name     string
	respond  Response
	delay    time.Duration
	asked    chan Request // test observes each Ask
	resolved chan string  // NotifyResolved outcomes
}

func (f *fakeChannel) Name() string { return f.name }
func (f *fakeChannel) Ask(ctx Context, r Request) (<-chan Response, error) {
	f.asked <- r
	rc := make(chan Response, 1)
	go func() {
		select {
		case <-time.After(f.delay):
			rc <- f.respond
		case <-ctx.Done():
		}
	}()
	return rc, nil
}
func (f *fakeChannel) NotifyResolved(id, outcome string) {
	select {
	case f.resolved <- outcome:
	default:
	}
}

func testEvent(cmd string) event.Event {
	return event.Event{
		ID: event.NewID(), Source: event.SourceShim, Action: event.ActionShell,
		Cmd: cmd, Argv: []string{cmd, "push"}, Raw: cmd + " push", Cwd: "/work",
	}
}

func TestSubmitApproveOnce(t *testing.T) {
	fc := &fakeChannel{name: "fake", respond: Response{Allow: true, By: "fake"}, asked: make(chan Request, 4), resolved: make(chan string, 4)}
	d := New([]Channel{fc}, 5*time.Second)
	dec := d.Submit(context.Background(), testEvent("git"), "git-push-ask")
	if dec.FinalEffect != event.Allow || dec.ApprovedBy != "fake" || dec.TimedOut {
		t.Fatalf("bad decision: %+v", dec)
	}
	select {
	case out := <-fc.resolved:
		if out != "approved by fake" {
			t.Fatalf("outcome %q", out)
		}
	default:
		t.Fatal("channel not notified of resolution")
	}
	if len(d.Pending()) != 0 {
		t.Fatal("pending list must be empty after resolution")
	}
}

func TestSubmitTimeoutDenies(t *testing.T) {
	// Channel that never answers.
	fc := &fakeChannel{name: "slow", delay: time.Hour, asked: make(chan Request, 4), resolved: make(chan string, 4)}
	d := New([]Channel{fc}, 150*time.Millisecond)
	start := time.Now()
	dec := d.Submit(context.Background(), testEvent("git"), "git-push-ask")
	if dec.FinalEffect != event.Deny || !dec.TimedOut {
		t.Fatalf("timeout must deny, got %+v", dec)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not enforced promptly")
	}
}

func TestFirstResponseWins(t *testing.T) {
	slow := &fakeChannel{name: "slow", respond: Response{Allow: false, By: "slow"}, delay: 200 * time.Millisecond, asked: make(chan Request, 4), resolved: make(chan string, 4)}
	fast := &fakeChannel{name: "fast", respond: Response{Allow: true, By: "fast"}, delay: 10 * time.Millisecond, asked: make(chan Request, 4), resolved: make(chan string, 4)}
	d := New([]Channel{slow, fast}, 5*time.Second)
	dec := d.Submit(context.Background(), testEvent("git"), "git-push-ask")
	if dec.ApprovedBy != "fast" || dec.FinalEffect != event.Allow {
		t.Fatalf("first response must win, got %+v", dec)
	}
}

func TestAllowRuleMemoizes(t *testing.T) {
	fc := &fakeChannel{name: "fake", respond: Response{Allow: true, AllowRule: true, By: "fake"}, asked: make(chan Request, 4), resolved: make(chan string, 4)}
	d := New([]Channel{fc}, 5*time.Second)
	ev := testEvent("git")
	if dec := d.Submit(context.Background(), ev, "git-push-ask"); dec.FinalEffect != event.Allow {
		t.Fatal("first submit must be approved")
	}
	// Drain the first Ask notification before asserting no second one.
	select {
	case <-fc.asked:
	default:
		t.Fatal("channel was never asked for the first request")
	}
	// Second identical action: memo hit — channel must NOT be asked again.
	dec := d.Submit(context.Background(), ev, "git-push-ask")
	if dec.FinalEffect != event.Allow || dec.ApprovedBy != "memo:git-push-ask" {
		t.Fatalf("memo hit expected, got %+v", dec)
	}
	select {
	case r := <-fc.asked:
		t.Fatalf("channel asked twice: %v", r.Event.ID)
	default:
	}
}

func TestResolveViaIPCPath(t *testing.T) {
	d := New(nil, 5*time.Second) // no channels at all
	done := make(chan event.Decision, 1)
	ev := testEvent("git")
	go func() { done <- d.Submit(context.Background(), ev, "git-push-ask") }()

	// Wait for pending registration.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(d.Pending()) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	pend := d.Pending()
	if len(pend) != 1 {
		t.Fatal("request never became pending")
	}
	if pend[0].Summary() != "$ git push" {
		t.Fatalf("summary = %q", pend[0].Summary())
	}
	// Resolve by prefix (like `agentvault approve allow <prefix>`).
	fullID, err := d.Resolve(pend[0].Event.ID[:8], true, "cli")
	if err != nil || fullID != pend[0].Event.ID {
		t.Fatalf("resolve: %v %q", err, fullID)
	}
	dec := <-done
	if dec.FinalEffect != event.Allow || dec.ApprovedBy != "cli" {
		t.Fatalf("IPC approval failed: %+v", dec)
	}
}

func TestResolveUnknownID(t *testing.T) {
	d := New(nil, time.Second)
	if _, err := d.Resolve("nonexistent", true, "cli"); err == nil {
		t.Fatal("expected error for unknown id")
	}
}

func TestMemoKeyDistinguishesTargets(t *testing.T) {
	a := memoKey("r", testEvent("git"))
	b := memoKey("r", testEvent("npm"))
	if a == b {
		t.Fatal("different commands must have different memo keys")
	}
}
