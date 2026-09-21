//go:build windows

package supervisor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"

	"github.com/aashish/agentvault/internal/ipc"
)

// listener is a loopback TCP socket with a per-session random token.
// Windows has no unix sockets; loopback + 128-bit token in the child's
// environment is the equivalent trust boundary (SPEC §3.3 note).
type listener struct {
	ln          net.Listener
	addr        string
	token       string
	sessionFile string
}

func startListener(session string) (*listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		_ = ln.Close()
		return nil, err
	}
	l := &listener{
		ln:    ln,
		addr:  ln.Addr().String(),
		token: hex.EncodeToString(tok),
	}
	// Publish endpoint for out-of-process clients (`agentvault approve`).
	if sf, err := json.Marshal(map[string]string{"addr": l.addr, "token": l.token}); err == nil {
		p := ipc.SessionFilePath(session)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		_ = os.WriteFile(p, sf, 0o600)
		l.sessionFile = p
	}
	return l, nil
}

func (l *listener) envVars() []string {
	return []string{
		"AGENTVAULT_ADDR=" + l.addr,
		"AGENTVAULT_TOKEN=" + l.token,
	}
}

func (l *listener) close() {
	_ = l.ln.Close()
	if l.sessionFile != "" {
		_ = os.Remove(l.sessionFile)
	}
}

// socketDir: no unix sockets on Windows — IPC is TCP, covered by the
// loopback allowance. Empty string = no unix rule needed.
func (l *listener) socketDir() string { return "" }

func (l *listener) serve(s *Supervisor) {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		go handleConn(conn, s, l.token)
	}
}

func handleConn(conn net.Conn, s *Supervisor, token string) {
	defer func() { _ = conn.Close() }()
	handleRequest(conn, s, token) // token checked inside, constant-time
}
