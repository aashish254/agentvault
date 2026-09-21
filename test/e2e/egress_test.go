//go:build !windows

package e2e

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
)

// egressPolicy: curl passes the shell layer unshimmed; egress allows only
// the test target host, everything else denied by egress.default.
const egressPolicyTmpl = `
version: 1
defaults: {action: deny}
rules:
  - name: allow-curl
    match:
      action: [shell.exec]
      cel: 'event.cmd == "curl"'
    effect: allow
shims:
  binaries: [curl]
egress:
  listen: "127.0.0.1:0"
  default: deny
  allow_hosts: ["TARGET_HOST"]
audit:
  path: "AUDIT_PATH_PLACEHOLDER"
`

// lanIP finds a non-loopback IPv4 so the agent's request actually
// traverses the proxy (127.0.0.1 is NO_PROXY'd by design).
func lanIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	t.Skip("no non-loopback IPv4 available")
	return ""
}

func TestEgressProxyEndToEnd(t *testing.T) {
	host := lanIP(t)

	// Target server bound to all interfaces so the LAN IP reaches it.
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "TARGET-DATA-OK")
	})}
	defer func() { _ = srv.Close() }()
	go func() { _ = srv.Serve(ln) }()

	h := New(t, "")
	policy := strings.ReplaceAll(egressPolicyTmpl, "AUDIT_PATH_PLACEHOLDER", h.VaultDir+"/audit.db")
	policy = strings.ReplaceAll(policy, "TARGET_HOST", host)
	writePolicyFile(t, h.Policy, policy)

	script := `
echo "agent-start"
curl -s --max-time 8 "http://` + host + `:` + port + `/data"
echo ""
echo "allow-exit=$?"
curl -s --max-time 8 "http://denied.invalid/secret"
echo ""
echo "deny-exit=$?"
echo "agent-end"
`
	scriptPath := writeScript(t, h, script)
	out, code := h.Run("bash", scriptPath)
	if code != 0 {
		t.Fatalf("agent exit = %d\n%s", code, out)
	}

	// Allowed host reached the real target through the proxy.
	if !strings.Contains(out, "TARGET-DATA-OK") {
		t.Fatalf("allowed egress must reach target:\n%s", out)
	}
	if !strings.Contains(out, "allow-exit=0") {
		t.Fatalf("allowed curl must exit 0:\n%s", out)
	}
	// Denied host gets the proxy's 403 body.
	if !strings.Contains(out, "blocked") || !strings.Contains(out, "egress.default") {
		t.Fatalf("denied egress must name egress.default:\n%s", out)
	}

	// Both decisions audited as net.egress.
	log := h.AuditLog()
	if !strings.Contains(log, `"action":"net.egress"`) {
		t.Fatalf("audit missing net.egress events:\n%s", log)
	}
	if !strings.Contains(log, `"host":"denied.invalid"`) {
		t.Fatalf("audit missing denied host:\n%s", log)
	}
}

// writeScript drops a shell script into the harness workdir.
func writeScript(t *testing.T, h *Harness, content string) string {
	t.Helper()
	p := h.WorkDir + "/agent.sh"
	writePolicyFile(t, p, content)
	return p
}
