// Package egress implements the network-egress channel (SPEC §1.2 #3):
// a loopback HTTP proxy handling CONNECT (HTTPS) and absolute-URI
// requests (plain HTTP). Every connection produces one net.egress event
// evaluated against the session policy; payloads are never inspected or
// logged — privacy by design.
package egress

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// DecideFunc maps a host:port to a verdict. The supervisor wires this to
// the policy engine (+ approval daemon for require_approval).
type DecideFunc func(host string, port int) event.Verdict

// Proxy is a loopback egress proxy.
type Proxy struct {
	Addr   string // actual listen address after Start
	Decide DecideFunc

	ln   net.Listener
	wg   sync.WaitGroup
	done chan struct{}
}

// Start listens on 127.0.0.1:0 (random port) and serves in the background.
func (p *Proxy) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	p.ln = ln
	p.Addr = ln.Addr().String()
	p.done = make(chan struct{})
	go p.serve()
	return nil
}

// Close stops accepting and waits for in-flight relays (bounded).
func (p *Proxy) Close() {
	close(p.done)
	_ = p.ln.Close()
	// Relays get their own 5s grace via done-channel checks in copy loops.
	time.Sleep(50 * time.Millisecond)
}

func (p *Proxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handle(conn)
		}()
	}
}

// handle reads one request (CONNECT or absolute-URI) and relays or blocks.
func (p *Proxy) handle(client net.Conn) {
	defer func() { _ = client.Close() }()
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	host, port := splitHostPort(req)
	if host == "" {
		writeHTTP(client, 400, "agentvault: cannot determine target host\n")
		return
	}

	v := p.Decide(host, port)
	if v.Effect != event.Allow {
		msg := fmt.Sprintf("agentvault: egress to %s:%d blocked", host, port)
		if v.RuleName != "" {
			msg += fmt.Sprintf(" by rule %q", v.RuleName)
		}
		if v.Message != "" {
			msg += ": " + v.Message
		}
		writeHTTP(client, 403, msg+"\n")
		return
	}

	if req.Method == http.MethodConnect {
		p.relayConnect(client, req, br, host, port)
		return
	}
	p.forwardPlain(client, req, br, host, port)
}

// relayConnect answers 200 and pipes bytes both directions until EOF.
func (p *Proxy) relayConnect(client net.Conn, req *http.Request, br *bufio.Reader, host string, port int) {
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 10*time.Second)
	if err != nil {
		writeHTTP(client, 502, "agentvault: target unreachable\n")
		return
	}
	defer func() { _ = target.Close() }()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	// Any bytes the client already sent past the CONNECT headers (rare)
	// must reach the target.
	if br.Buffered() > 0 {
		_, _ = io.Copy(target, br)
	}
	_ = client.SetReadDeadline(time.Time{})
	relayBoth(client, target)
}

// forwardPlain rewrites an absolute-URI request to origin form and
// forwards it, streaming the response back. Single round-trip; enough
// for agent HTTP calls.
func (p *Proxy) forwardPlain(client net.Conn, req *http.Request, br *bufio.Reader, host string, port int) {
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 10*time.Second)
	if err != nil {
		writeHTTP(client, 502, "agentvault: target unreachable\n")
		return
	}
	defer func() { _ = target.Close() }()

	req.RequestURI = "" // origin form required by net/http.Write
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Connection")
	req.Close = true
	if err := req.Write(target); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(target), req)
	if err != nil {
		writeHTTP(client, 502, "agentvault: bad target response\n")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_ = resp.Write(client)
}

// relayBoth copies bidirectionally until either side closes.
func relayBoth(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if tc, ok := a.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

// splitHostPort extracts host/port from CONNECT authority or URL Host.
func splitHostPort(req *http.Request) (string, int) {
	authority := req.Host
	if authority == "" && req.URL != nil {
		authority = req.URL.Host
	}
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		// No port: default by scheme (443 for CONNECT, 80 otherwise).
		host = strings.TrimSuffix(authority, ":")
		if req.Method == http.MethodConnect {
			return host, 443
		}
		return host, 80
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return host, 0
	}
	return host, port
}

// writeHTTP emits a minimal response with a text body.
func writeHTTP(w io.Writer, code int, body string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}
