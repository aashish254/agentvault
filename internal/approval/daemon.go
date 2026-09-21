// Package approval implements the approval daemon (SPEC §4.5):
// require_approval events become pending requests, fanned out to every
// notification channel (Telegram, TTY, IPC). First decisive human
// response wins; timeout means deny — fail closed.
package approval

import (
	"fmt"
	"sync"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// Response is a human's answer to one approval request.
type Response struct {
	Allow     bool   // false = deny
	AllowRule bool   // memoize this (rule, action, target) for the session
	By        string // "telegram:<chat>" | "tty" | "cli"
}

// Request is one pending approval.
type Request struct {
	Event     event.Event
	RuleName  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Summary renders the one-line human description of what's being asked.
func (r Request) Summary() string {
	e := r.Event
	switch e.Action {
	case event.ActionShell:
		return "$ " + e.Raw
	case event.ActionNetEgress:
		return fmt.Sprintf("network: %s:%d", e.Host, e.Port)
	case event.ActionMCPTool:
		return fmt.Sprintf("mcp: %s/%s", e.Server, e.Tool)
	default:
		return fmt.Sprintf("%s: %s", e.Action, e.Path)
	}
}

// Channel delivers approval requests to a human and reports responses.
type Channel interface {
	Name() string
	// Ask returns a channel yielding at most one Response.
	Ask(ctx Context, r Request) (<-chan Response, error)
	// NotifyResolved lets a channel update its UI when the request was
	// resolved elsewhere. Best-effort.
	NotifyResolved(eventID string, outcome string)
}

// Daemon owns pending requests, the memo cache, and resolution.
type Daemon struct {
	mu       sync.RWMutex
	pending  map[string]*pendingReq
	memo     *memoCache
	channels []Channel
	timeout  time.Duration
}

type pendingReq struct {
	req      Request
	respond  chan Response // buffered(1); IPC resolutions land here
	resolved bool
	outcome  string
}

// New builds a daemon. channels may be empty — IPC resolution via
// `agentvault approve` always works regardless.
func New(channels []Channel, timeout time.Duration) *Daemon {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Daemon{
		pending:  make(map[string]*pendingReq),
		memo:     newMemoCache(1024),
		channels: channels,
		timeout:  timeout,
	}
}

// Pending snapshots unresolved requests for `agentvault approve list`.
func (d *Daemon) Pending() []Request {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Request, 0, len(d.pending))
	for _, pr := range d.pending {
		if !pr.resolved {
			out = append(out, pr.req)
		}
	}
	return out
}

// Resolve answers a pending request by event id or unique ≥6-char prefix.
func (d *Daemon) Resolve(idOrPrefix string, allow bool, by string) (string, error) {
	d.mu.RLock()
	var target *pendingReq
	for id, pr := range d.pending {
		if pr.resolved {
			continue
		}
		if id == idOrPrefix || (len(idOrPrefix) >= 6 && len(id) >= len(idOrPrefix) && id[:len(idOrPrefix)] == idOrPrefix) {
			if target != nil {
				d.mu.RUnlock()
				return "", fmt.Errorf("prefix %q is ambiguous", idOrPrefix)
			}
			target = pr
		}
	}
	d.mu.RUnlock()
	if target == nil {
		return "", fmt.Errorf("no pending request %q", idOrPrefix)
	}
	target.respond <- Response{Allow: allow, By: by}
	return target.req.Event.ID, nil
}

func (d *Daemon) removePending(id string) {
	d.mu.Lock()
	delete(d.pending, id)
	d.mu.Unlock()
}

func (d *Daemon) markResolved(id string, pr *pendingReq, outcome string) {
	d.mu.Lock()
	pr.resolved = true
	pr.outcome = outcome
	d.mu.Unlock()
	for _, ch := range d.channels {
		ch.NotifyResolved(id, outcome)
	}
}

func outcomeOf(r Response) string {
	if r.Allow {
		if r.AllowRule {
			return "approved (rule memoized) by " + r.By
		}
		return "approved by " + r.By
	}
	return "denied by " + r.By
}
