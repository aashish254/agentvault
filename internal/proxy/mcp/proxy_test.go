//go:build !windows

package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aashish/agentvault/internal/event"
)

func fakeServer(t *testing.T) []string {
	t.Helper()
	p := "testdata/fake_server.sh"
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	return []string{"sh", p}
}

// runProxy drives the proxy with scripted input and collects output.
func runProxy(t *testing.T, eval EvalFunc, input []string) []string {
	t.Helper()
	var in bytes.Buffer
	for _, l := range input {
		in.WriteString(l + "\n")
	}
	var out bytes.Buffer
	p := &Proxy{
		ServerName: "testfs",
		Command:    fakeServer(t),
		Eval:       eval,
		Stdin:      &in,
		Stdout:     &out,
	}
	if err := p.Run(); err != nil {
		t.Fatal(err)
	}
	var lines []string
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func TestPassthroughByteIdentical(t *testing.T) {
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
	toolsList := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	eval := func(e event.Event) event.Verdict {
		t.Fatalf("eval must not be called for non-tool traffic: %+v", e)
		return event.Verdict{Effect: event.Deny}
	}
	lines := runProxy(t, eval, []string{init, toolsList})
	if len(lines) != 2 {
		t.Fatalf("want 2 responses, got %d: %v", len(lines), lines)
	}
	for i, wantID := range []int{1, 2} {
		var resp struct {
			ID int `json:"id"`
		}
		if json.Unmarshal([]byte(lines[i]), &resp) != nil || resp.ID != wantID {
			t.Fatalf("response %d: want id %d, got %s", i, wantID, lines[i])
		}
	}
}

func TestToolCallAllowed(t *testing.T) {
	call := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x.txt"}}}`
	var got event.Event
	eval := func(e event.Event) event.Verdict {
		got = e
		return event.Verdict{Effect: event.Allow, RuleName: "ok"}
	}
	lines := runProxy(t, eval, []string{call})
	if len(lines) != 1 {
		t.Fatalf("want 1 response, got %v", lines)
	}
	if !strings.Contains(lines[0], `"result"`) {
		t.Fatalf("allowed call must reach the server, got %s", lines[0])
	}
	if got.Action != event.ActionFSRead || got.Path != "/tmp/x.txt" || got.Tool != "read_file" || got.Server != "testfs" {
		t.Fatalf("bad event mapping: %+v", got)
	}
}

func TestToolCallDenied(t *testing.T) {
	call := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/home/u/.ssh/id_rsa"}}}`
	eval := func(e event.Event) event.Verdict {
		if e.Action != event.ActionFSDelete {
			t.Errorf("delete_file must map to fs.delete, got %s", e.Action)
		}
		return event.Verdict{Effect: event.Deny, RuleName: "protect-credentials", Message: "off-limits"}
	}
	lines := runProxy(t, eval, []string{call})
	if len(lines) != 1 {
		t.Fatalf("want 1 response, got %v", lines)
	}
	var resp struct {
		ID    int `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("deny response not valid JSON-RPC: %v\n%s", err, lines[0])
	}
	if resp.ID != 9 || resp.Error.Code != -32000 {
		t.Fatalf("bad deny response: %s", lines[0])
	}
	if !strings.Contains(resp.Error.Message, "protect-credentials") {
		t.Fatalf("deny message must name the rule: %s", resp.Error.Message)
	}
}

func TestToolCallFailClosedWithoutEval(t *testing.T) {
	call := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	lines := runProxy(t, nil, []string{call}) // Eval = nil
	if len(lines) != 1 || !strings.Contains(lines[0], "-32000") {
		t.Fatalf("nil eval must fail closed, got %v", lines)
	}
}

func TestMalformedLineForwardedVerbatim(t *testing.T) {
	eval := func(e event.Event) event.Verdict {
		t.Fatal("eval must not fire on garbage")
		return event.Verdict{}
	}
	lines := runProxy(t, eval, []string{"this is not json"})
	if len(lines) != 1 || !strings.Contains(lines[0], `"id":0`) {
		t.Fatalf("garbage must be forwarded to the server, got %v", lines)
	}
}

func TestMoveFileMapsSourceAsPath(t *testing.T) {
	var got event.Event
	eval := func(e event.Event) event.Verdict {
		got = e
		return event.Verdict{Effect: event.Deny, RuleName: "r"}
	}
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"move_file","arguments":{"source":"/a/b","destination":"/c/d"}}}`
	runProxy(t, eval, []string{call})
	if got.Action != event.ActionFSDelete || got.Path != "/a/b" {
		t.Fatalf("move_file must map source→path as fs.delete, got %+v", got)
	}
}

func TestNotificationPassthrough(t *testing.T) {
	note := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	eval := func(e event.Event) event.Verdict {
		t.Fatal("eval must not fire on notifications")
		return event.Verdict{}
	}
	lines := runProxy(t, eval, []string{note})
	if len(lines) != 1 {
		t.Fatalf("notification not forwarded, got %v", lines)
	}
}

func TestDenyResponseValidJSON(t *testing.T) {
	out := denyResponse(json.RawMessage("null"), "r", "")
	if !strings.Contains(string(out), `"code":-32000`) {
		t.Fatalf("bad deny response: %s", out)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
}

func TestFramerLastLineNoNewline(t *testing.T) {
	f := newFramer(strings.NewReader("line1\nline2")) // no trailing \n
	l1, err1 := f.next()
	l2, err2 := f.next()
	_, err3 := f.next()
	if string(l1) != "line1" || err1 != nil {
		t.Fatalf("l1: %q %v", l1, err1)
	}
	if string(l2) != "line2" || err2 != nil {
		t.Fatalf("l2: %q %v", l2, err2)
	}
	if err3 == nil {
		t.Fatal("third read must be EOF")
	}
}
