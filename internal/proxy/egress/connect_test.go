package egress

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// startTarget launches a raw TCP server that replies "hello" to anything.
func startTarget(t *testing.T) (addr string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, 4)
				_, _ = io.ReadAtLeast(c, b, 1)
				_, _ = c.Write([]byte("hello"))
			}()
		}
	}()
	host, ps, _ := net.SplitHostPort(ln.Addr().String())
	var p int
	if _, err := fmt.Sscanf(ps, "%d", &p); err != nil {
		t.Fatal(err)
	}
	return host, p
}

func startProxy(t *testing.T, decide DecideFunc) string {
	t.Helper()
	p := &Proxy{Decide: decide}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p.Addr
}

func TestConnectAllowed(t *testing.T) {
	host, port := startTarget(t)
	proxyAddr := startProxy(t, func(h string, pt int) event.Verdict {
		if h != host || pt != port {
			t.Errorf("decide got %s:%d, want %s:%d", h, pt, host, port)
		}
		return event.Verdict{Effect: event.Allow}
	})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	fmt.Fprintf(conn, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("want 200, got %s", status)
	}
	// Consume headers.
	for {
		l, _ := br.ReadString('\n')
		if l == "\r\n" {
			break
		}
	}
	// Tunneled bytes must flow.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("tunnel broken: %q", buf)
	}
}

func TestConnectDenied(t *testing.T) {
	proxyAddr := startProxy(t, func(string, int) event.Verdict {
		return event.Verdict{Effect: event.Deny, RuleName: "net-egress-ask", Message: "nope"}
	})
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	fmt.Fprintf(conn, "CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
	resp, _ := io.ReadAll(conn)
	s := string(resp)
	if !strings.Contains(s, "403") || !strings.Contains(s, "net-egress-ask") {
		t.Fatalf("deny must be 403 naming the rule:\n%s", s)
	}
}

func TestPlainHTTPForward(t *testing.T) {
	// Plain HTTP (absolute-URI) through the proxy to a real HTTP server.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "proxied-ok:"+r.URL.Path)
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://")

	proxyAddr := startProxy(t, func(string, int) event.Verdict {
		return event.Verdict{Effect: event.Allow}
	})

	proxyURL := "http://" + proxyAddr
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParse(proxyURL))}}
	resp, err := client.Get("http://" + targetHost + "/some/path")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "proxied-ok:/some/path" {
		t.Fatalf("plain forward broken: %q", body)
	}
}

func TestPlainHTTPDenied(t *testing.T) {
	proxyAddr := startProxy(t, func(string, int) event.Verdict {
		return event.Verdict{Effect: event.Deny, RuleName: "egress.default"}
	})
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParse("http://" + proxyAddr))}}
	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 403 {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestSplitHostPort(t *testing.T) {
	mk := func(method, host string) *http.Request {
		return &http.Request{Method: method, Host: host}
	}
	h, p := splitHostPort(mk(http.MethodConnect, "api.example.com:443"))
	if h != "api.example.com" || p != 443 {
		t.Fatalf("authority: %s:%d", h, p)
	}
	h, p = splitHostPort(mk(http.MethodConnect, "api.example.com"))
	if h != "api.example.com" || p != 443 {
		t.Fatalf("CONNECT default: %s:%d", h, p)
	}
	h, p = splitHostPort(mk(http.MethodGet, "example.com"))
	if h != "example.com" || p != 80 {
		t.Fatalf("HTTP default: %s:%d", h, p)
	}
}
