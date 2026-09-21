package approval

import (
	"context"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// Context aliases context.Context so the Channel interface reads cleanly.
type Context = context.Context

// Submit registers the event, notifies channels, and blocks until a
// response or the timeout (→ deny, TimedOut=true). Memo hits return
// instantly without touching any channel.
func (d *Daemon) Submit(ctx context.Context, e event.Event, ruleName string) event.Decision {
	key := memoKey(ruleName, e)
	if d.memo.hit(key) {
		return event.Decision{EventID: e.ID, FinalEffect: event.Allow, ApprovedBy: "memo:" + ruleName}
	}

	now := time.Now()
	pr := &pendingReq{
		req:     Request{Event: e, RuleName: ruleName, CreatedAt: now, ExpiresAt: now.Add(d.timeout)},
		respond: make(chan Response, 1),
	}
	d.mu.Lock()
	d.pending[e.ID] = pr
	d.mu.Unlock()
	defer d.removePending(e.ID)

	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// Fan-in: every source (channels + IPC respond chan) feeds agg once.
	agg := make(chan Response, 1)
	feed := func(rc <-chan Response) {
		select {
		case r := <-rc:
			select {
			case agg <- r:
			default:
			}
		case <-ctx.Done():
		}
	}
	for _, ch := range d.channels {
		if rc, err := ch.Ask(ctx, pr.req); err == nil && rc != nil {
			go feed(rc)
		}
	}
	go feed(pr.respond)

	var dec event.Decision
	select {
	case r := <-agg:
		eff := event.Deny
		if r.Allow {
			eff = event.Allow
		}
		dec = event.Decision{EventID: e.ID, FinalEffect: eff, ApprovedBy: r.By, Waited: time.Since(now)}
		if r.Allow && r.AllowRule {
			d.memo.store(key)
		}
		d.markResolved(e.ID, pr, outcomeOf(r))
	case <-ctx.Done():
		dec = event.Decision{
			EventID: e.ID, FinalEffect: event.Deny,
			Waited: time.Since(now), TimedOut: true,
		}
		d.markResolved(e.ID, pr, "timed out — denied (fail closed)")
	}
	return dec
}
