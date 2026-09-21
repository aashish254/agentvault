//go:build !windows

package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// target is a discovered live session endpoint (unix: socket path).
type target struct {
	address string
}

// dialEnv connects using AGENTVAULT_SOCK from the environment.
func dialEnv(timeout time.Duration) (net.Conn, error) {
	sock := os.Getenv("AGENTVAULT_SOCK")
	if sock == "" {
		return nil, fmt.Errorf("AGENTVAULT_SOCK not set — not running under agentvault?")
	}
	// #nosec G704 -- sock is our own session socket path from the supervisor.
	return net.DialTimeout("unix", sock, timeout)
}

func dialTarget(t target, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", t.address, timeout)
}

// discover finds live session sockets under /tmp/av-<uid>/, newest first.
func discover(sessionFilter string) (target, error) {
	dir := filepath.Join("/tmp", fmt.Sprintf("av-%d", os.Getuid()))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return target{}, ErrNoSession
	}
	type cand struct {
		path string
		mod  time.Time
	}
	var cands []cand
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sock") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".sock")
		if sessionFilter != "" && id != sessionFilter &&
			(len(sessionFilter) < 6 || !strings.HasPrefix(id, sessionFilter)) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		cands = append(cands, cand{filepath.Join(dir, e.Name()), info.ModTime()})
	}
	// Newest first; skip dead sockets (crashed supervisor leaves them).
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod.After(cands[j].mod) })
	for _, c := range cands {
		conn, err := net.DialTimeout("unix", c.path, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return target{address: c.path}, nil
		}
		_ = os.Remove(c.path) // reap stale socket
	}
	return target{}, ErrNoSession
}
