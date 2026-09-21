package mcp

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/aashish/agentvault/internal/event"
)

// EvalFunc decides a verdict for an intercepted event. The CLI wires
// this to the session supervisor over IPC; tests inject stubs.
type EvalFunc func(event.Event) event.Verdict

// Proxy is one wrapped MCP server: the agent talks stdio to us, we talk
// stdio to the real server.
type Proxy struct {
	ServerName string
	Command    []string // the real MCP server command line
	Eval       EvalFunc // required for tools/call; nil = fail closed
	// Stdin/Stdout default to os.Stdin/os.Stdout (the agent side);
	// injectable for tests.
	Stdin  io.Reader
	Stdout io.Writer
}

// agentWriter serializes writes to the agent side: deny responses from
// the read loop and response bytes from the copy goroutine must never
// interleave mid-message.
type agentWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (a *agentWriter) writeLine(b []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.w.Write(append(b, '\n'))
	return err
}

func (a *agentWriter) writeRaw(b []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.w.Write(b)
	return err
}

// Run starts the real server and proxies until EOF or process exit.
func (p *Proxy) Run() error {
	if len(p.Command) == 0 {
		return fmt.Errorf("mcp proxy: no server command after --")
	}
	in := p.Stdin
	if in == nil {
		in = os.Stdin
	}
	out := p.Stdout
	if out == nil {
		out = os.Stdout
	}
	aw := &agentWriter{w: out}

	// #nosec G204 -- the wrapped server command is the configured input.
	srv := exec.Command(p.Command[0], p.Command[1:]...)
	srvIn, err := srv.StdinPipe()
	if err != nil {
		return err
	}
	srvOut, err := srv.StdoutPipe()
	if err != nil {
		return err
	}
	srv.Stderr = os.Stderr // server diagnostics go to the user verbatim
	if err := srv.Start(); err != nil {
		return fmt.Errorf("mcp proxy: start %q: %w", p.Command[0], err)
	}
	defer func() { _ = srv.Process.Kill() }()

	// Server → agent: verbatim copy (responses are never intercepted).
	// Explicit read loop — no io.Copy fast paths.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			n, rerr := srvOut.Read(buf)
			if n > 0 {
				if werr := aw.writeRaw(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	// Agent → server: intercept tools/call, pass everything else raw.
	fr := newFramer(in)
	for {
		line, err := fr.next()
		if len(line) == 0 && err != nil {
			break
		}
		m, perr := parseMsg(line)
		if perr != nil || !m.isToolCall() {
			if _, werr := srvIn.Write(append(line, '\n')); werr != nil {
				break // server gone
			}
		} else {
			ev := buildEvent(p.ServerName, m)
			v := p.evaluate(ev)
			if v.Effect == event.Allow {
				if _, werr := srvIn.Write(append(line, '\n')); werr != nil {
					break
				}
			} else {
				if werr := aw.writeLine(denyResponse(m.ID, v.RuleName, v.Message)); werr != nil {
					break // agent gone
				}
			}
		}
		if err != nil { // io.EOF after final line
			break
		}
	}
	_ = srvIn.Close()
	wg.Wait()
	return nil
}

// evaluate applies the EvalFunc; nil or error → fail closed.
func (p *Proxy) evaluate(ev event.Event) event.Verdict {
	if p.Eval == nil {
		return event.Verdict{Effect: event.Deny, Message: "no policy evaluator attached (fail closed)"}
	}
	return p.Eval(ev)
}
