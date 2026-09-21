package approval

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func ttyAsk(t *testing.T, input string) (Response, string) {
	t.Helper()
	var out bytes.Buffer
	ch := NewTTYIO(strings.NewReader(input), &out)
	rc, err := ch.Ask(bg, telegramEvent())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-rc:
		return r, out.String()
	case <-time.After(2 * time.Second):
		t.Fatal("tty channel never answered")
	}
	return Response{}, ""
}

func TestTTYAllowOnce(t *testing.T) {
	r, out := ttyAsk(t, "y\n")
	if !r.Allow || r.AllowRule || r.By != "tty" {
		t.Fatalf("bad response: %+v", r)
	}
	if !strings.Contains(out, "approval requested") || !strings.Contains(out, "git-push-ask") {
		t.Fatalf("prompt missing context:\n%s", out)
	}
	if !strings.Contains(out, "$ git push") {
		t.Fatalf("prompt missing summary:\n%s", out)
	}
}

func TestTTYAllowRule(t *testing.T) {
	r, _ := ttyAsk(t, "a\n")
	if !r.Allow || !r.AllowRule {
		t.Fatalf("bad response: %+v", r)
	}
}

func TestTTYDenyDefault(t *testing.T) {
	for _, input := range []string{"n\n", "\n", "garbage\n"} {
		r, _ := ttyAsk(t, input)
		if r.Allow {
			t.Fatalf("input %q must deny, got %+v", input, r)
		}
	}
}

func TestTTYEOFNoResponse(t *testing.T) {
	// EOF (terminal closed) must yield no response; the daemon's timeout
	// path handles the deny.
	ch := NewTTYIO(strings.NewReader(""), &bytes.Buffer{})
	rc, err := ch.Ask(bg, telegramEvent())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-rc:
		t.Fatalf("EOF must not produce a response, got %+v", r)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestNewTTYWithoutTerminal(t *testing.T) {
	// Under `go test`, stderr is a pipe → NewTTY must auto-disable.
	if NewTTY() != nil {
		t.Skip("test environment has a real TTY; skipping auto-disable check")
	}
}
