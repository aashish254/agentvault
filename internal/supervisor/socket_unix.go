//go:build !windows

package supervisor

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/aashish/agentvault/internal/event"
)

// listener is a unix-domain socket at <vault>/run/<session>.sock,
// mode 0600. Filesystem permissions are the auth mechanism: only the
// owning user can connect.
type listener struct {
	ln   net.Listener
	path string
}

// startListener creates the session socket under /tmp/av-<uid>/
// (NOT under the vault dir): unix socket paths are limited to ~104
// bytes, and vault dirs under $TMPDIR on macOS blow right past it.
// The dir is 0700 and ownership-verified to resist pre-creation attacks.
func startListener(session string) (*listener, error) {
	dir := filepath.Join("/tmp", fmt.Sprintf("av-%d", os.Getuid()))
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			return nil, fmt.Errorf("socket dir %s has unsafe mode %v", dir, info.Mode().Perm())
		}
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, session+".sock")
	_ = os.Remove(path) // stale socket from a crashed session
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return &listener{ln: ln, path: path}, nil
}

// envVars exported into the child process.
func (l *listener) envVars() []string {
	return []string{"AGENTVAULT_SOCK=" + l.path}
}

func (l *listener) close() {
	_ = l.ln.Close()
	_ = os.Remove(l.path)
}

// serve accepts shim connections until the listener closes.
// Each connection handles one request/response and dies.
func (l *listener) serve(s *Supervisor) {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return // closed
		}
		go handleConn(conn, s)
	}
}

func handleConn(conn net.Conn, s *Supervisor) {
	defer func() { _ = conn.Close() }()
	var req event.EvalRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil || req.Type != "eval" {
		return // malformed: no response, shim fails closed
	}
	v := s.Evaluate(req.Event)
	resp := event.EvalResponse{
		Type:     "verdict",
		Effect:   v.Effect,
		RuleName: v.RuleName,
		Message:  v.Message,
	}
	_ = json.NewEncoder(conn).Encode(resp)
}
