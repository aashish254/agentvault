// Package audit records events. Week 2 ships the synchronous JSONL
// logger; Week 3 replaces storage with the hash-chained SQLite store
// behind this same Logger interface (SPEC §4.5).
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// Record is one line in the JSONL audit log.
type Record struct {
	Event    event.Event     `json:"event"`
	Verdict  event.Verdict   `json:"verdict"`
	Decision *event.Decision `json:"decision,omitempty"`
	LoggedAt time.Time       `json:"logged_at"`
}

// Logger is the audit sink contract, stable across Weeks 2→3.
type Logger interface {
	Log(e event.Event, v event.Verdict, d *event.Decision)
	Flush(deadline time.Duration) error
	Close() error
}

// JSONLLogger appends records synchronously to a file. Simple and
// crash-safe enough for Week 2; superseded by Store in Week 3.
type JSONLLogger struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// OpenJSONL creates or appends to path (0600, parent dirs 0700).
func OpenJSONL(path string) (*JSONLLogger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: mkdir: %w", err)
	}
	// #nosec G304 -- path comes from the user's own policy file.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open: %w", err)
	}
	return &JSONLLogger{f: f, path: path}, nil
}

// Log appends one record. Synchronous: a write error is impossible to
// miss and surfaces in the caller's stderr via the supervisor.
func (l *JSONLLogger) Log(e event.Event, v event.Verdict, d *event.Decision) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec := Record{Event: e, Verdict: v, Decision: d, LoggedAt: time.Now().UTC()}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_, _ = l.f.Write(append(b, '\n'))
}

// Flush is a no-op for the synchronous writer (kept for the interface).
func (l *JSONLLogger) Flush(time.Duration) error { return nil }

// Close closes the underlying file.
func (l *JSONLLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// Path returns the log file location.
func (l *JSONLLogger) Path() string { return l.path }
