// Package ipc centralizes how out-of-process clients (shims, the
// approve CLI) reach a running supervisor. Unix: per-session sockets
// under /tmp/av-<uid>/; Windows: loopback TCP with token files under
// <vault>/run/.
package ipc

import (
	"fmt"
	"net"
	"os"
	"time"
)

// DialEnv connects using the ambient AGENTVAULT_* environment (shims).
func DialEnv(timeout time.Duration) (net.Conn, error) {
	return dialEnv(timeout)
}

// DialLatest connects to the most recently modified live session
// (the approve CLI's default target). sessionFilter, when non-empty,
// selects a specific session id (or unique prefix).
func DialLatest(sessionFilter string, timeout time.Duration) (net.Conn, error) {
	target, err := discover(sessionFilter)
	if err != nil {
		return nil, err
	}
	return dialTarget(target, timeout)
}

// EnvToken returns the session token from the environment (empty on unix).
func EnvToken() string { return os.Getenv("AGENTVAULT_TOKEN") }

// ErrNoSession is returned when no running supervisor is discoverable.
var ErrNoSession = fmt.Errorf("no running agentvault session found")
