//go:build windows

package supervisor

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"

	"github.com/aashish/agentvault/internal/event"
)

// listener is a loopback TCP socket with a per-session random token.
// Windows has no unix sockets; loopback + 128-bit token in the child's
// environment is the equivalent trust boundary (SPEC §3.3 note).
type listener struct {
	ln    net.Listener
	addr  string
	token string
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
	return &listener{
		ln:    ln,
		addr:  ln.Addr().String(),
		token: hex.EncodeToString(tok),
	}, nil
}

func (l *listener) envVars() []string {
	return []string{
		"AGENTVAULT_ADDR=" + l.addr,
		"AGENTVAULT_TOKEN=" + l.token,
	}
}

func (l *listener) close() { _ = l.ln.Close() }

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
	var req event.EvalRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil || req.Type != "eval" {
		return
	}
	// Constant-time compare: a wrong token gets silence, not a verdict.
	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(token)) != 1 {
		return
	}
	v := s.Evaluate(req.Event)
	_ = json.NewEncoder(conn).Encode(event.EvalResponse{
		Type:     "verdict",
		Effect:   v.Effect,
		RuleName: v.RuleName,
		Message:  v.Message,
	})
}
