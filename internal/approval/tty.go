package approval

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// TTYChannel prompts on the terminal. Injected reader/writer make it
// testable without a real TTY; NewTTY wires os.Stderr + /dev/tty input.
type TTYChannel struct {
	in  *bufio.Reader
	out io.Writer
}

// NewTTY returns a TTY channel, or nil when no terminal is attached
// (e.g. stderr is a pipe under test harnesses — auto-disable per SPEC).
func NewTTY() *TTYChannel {
	if fi, err := os.Stderr.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return nil
	}
	// Prompt on stderr (stdout belongs to the child agent); read from
	// /dev/tty so we work even when stdin is piped.
	tty, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		return nil
	}
	return &TTYChannel{in: bufio.NewReader(tty), out: os.Stderr}
}

// NewTTYIO builds a channel over arbitrary streams (tests).
func NewTTYIO(in io.Reader, out io.Writer) *TTYChannel {
	return &TTYChannel{in: bufio.NewReader(in), out: out}
}

func (t *TTYChannel) Name() string { return "tty" }

func (t *TTYChannel) Ask(ctx Context, r Request) (<-chan Response, error) {
	resp := make(chan Response, 1)
	fmt.Fprintf(t.out, "\n🛡  AgentVault — approval requested (rule %q)\n   %s\n   cwd: %s\n   [y] allow once · [a] allow this rule · [N] deny  (expires %s): ",
		r.RuleName, r.Summary(), r.Event.Cwd, r.ExpiresAt.Format("15:04:05"))
	go func() {
		line, err := t.in.ReadString('\n')
		fmt.Fprint(t.out, "\n")
		if err != nil {
			return // ctx timeout will deny
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			resp <- Response{Allow: true, By: "tty"}
		case "a", "always":
			resp <- Response{Allow: true, AllowRule: true, By: "tty"}
		default:
			resp <- Response{Allow: false, By: "tty"}
		}
	}()
	return resp, nil
}

func (t *TTYChannel) NotifyResolved(eventID string, outcome string) {
	fmt.Fprintf(t.out, "🛡  request %s %s\n", shortID(eventID), outcome)
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[len(id)-8:]
	}
	return id
}
