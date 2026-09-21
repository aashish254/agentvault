//go:build windows

package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aashish/agentvault/internal/paths"
)

type target struct {
	address string
	token   string
}

func dialEnv(timeout time.Duration) (net.Conn, error) {
	addr := os.Getenv("AGENTVAULT_ADDR")
	if addr == "" {
		return nil, fmt.Errorf("AGENTVAULT_ADDR not set — not running under agentvault?")
	}
	return net.DialTimeout("tcp", addr, timeout)
}

func dialTarget(t target, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", t.address, timeout)
}

// sessionFile is written by the Windows listener so out-of-process
// clients can find the address + token for a session.
type sessionFile struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
}

// SessionFilePath is where the supervisor publishes its endpoint.
func SessionFilePath(session string) string {
	return filepath.Join(paths.VaultDir(), "run", session+".json")
}

// discover reads <vault>/run/*.json, newest first.
func discover(sessionFilter string) (target, error) {
	dir := filepath.Join(paths.VaultDir(), "run")
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
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if sessionFilter != "" && id != sessionFilter &&
			!(len(sessionFilter) >= 6 && strings.HasPrefix(id, sessionFilter)) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		cands = append(cands, cand{filepath.Join(dir, e.Name()), info.ModTime()})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod.After(cands[j].mod) })
	for _, c := range cands {
		b, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		var sf sessionFile
		if json.Unmarshal(b, &sf) != nil || sf.Addr == "" {
			continue
		}
		conn, err := net.DialTimeout("tcp", sf.Addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return target{address: sf.Addr, token: sf.Token}, nil
		}
		_ = os.Remove(c.path)
	}
	return target{}, ErrNoSession
}
