package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// Logger is the async, non-blocking audit writer (SPEC §4.5).
// Log never blocks the agent's hot path: on a full channel it spills to
// an overflow file and counts the spill. A single writer goroutine owns
// the chain state. Flush is a channel barrier: when it returns, every
// record logged before it is durably committed.
type Logger struct {
	store    *Store
	ch       chan Record
	flushCh  chan chan error // barrier: writer flushes, then signals
	done     chan struct{}
	overflow *os.File
	dropped  atomic.Int64
	wg       sync.WaitGroup
}

const (
	chanCapacity  = 1 << 16 // 65k records ≈ burst-proof for any plausible agent
	batchMax      = 500
	flushInterval = 50 * time.Millisecond
)

// NewLogger starts the writer goroutine. overflowPath receives spilled
// records if the channel saturates.
func NewLogger(store *Store, overflowPath string) (*Logger, error) {
	l := &Logger{
		store:   store,
		ch:      make(chan Record, chanCapacity),
		flushCh: make(chan chan error),
		done:    make(chan struct{}),
	}
	if err := os.MkdirAll(filepath.Dir(overflowPath), 0o700); err == nil {
		// #nosec G304 -- path derives from the vault dir, not user input.
		f, err := os.OpenFile(overflowPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			l.overflow = f
		}
	}
	l.wg.Add(1)
	go l.writer()
	return l, nil
}

// Log enqueues a record. Non-blocking: spills to overflow on saturation.
func (l *Logger) Log(e event.Event, v event.Verdict, d *event.Decision) {
	rec := Record{Event: e, Verdict: v, Decision: d, LoggedAt: time.Now().UTC()}
	select {
	case l.ch <- rec:
	default:
		l.dropped.Add(1)
		l.spill(rec)
	}
}

// Dropped reports how many records spilled to the overflow file.
func (l *Logger) Dropped() int64 { return l.dropped.Load() }

func (l *Logger) spill(rec Record) {
	if l.overflow == nil {
		return
	}
	if b, err := json.Marshal(rec); err == nil {
		_, _ = l.overflow.Write(append(b, '\n'))
	}
}

// writer is the single goroutine allowed to mutate the chain.
// It greedily drains the channel up to batchMax before committing, so
// bursts stream through instead of trickling at one batch per tick.
func (l *Logger) writer() {
	defer l.wg.Done()
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	batch := make([]Record, 0, batchMax)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := l.store.InsertBatch(batch); err != nil {
			for _, r := range batch {
				l.dropped.Add(1)
				l.spill(r)
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case rec := <-l.ch:
			batch = append(batch, rec)
			// Greedy drain: pull everything pending without blocking.
		drain:
			for len(batch) < batchMax {
				select {
				case rec := <-l.ch:
					batch = append(batch, rec)
				default:
					break drain
				}
			}
			if len(batch) >= batchMax {
				flush()
			}
		case resp := <-l.flushCh:
			flush()
			resp <- nil
		case <-ticker.C:
			flush()
		case <-l.done:
			for len(l.ch) > 0 {
				batch = append(batch, <-l.ch)
			}
			flush()
			return
		}
	}
}

// Flush sends a barrier through the channel: when it returns nil, every
// record logged before the call is durably committed. Deadline-bounded.
func (l *Logger) Flush(deadline time.Duration) error {
	resp := make(chan error, 1)
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case l.flushCh <- resp:
	case <-timer.C:
		return fmt.Errorf("audit: flush: deadline sending barrier")
	case <-l.done:
		return fmt.Errorf("audit: flush: logger closed")
	}
	select {
	case err := <-resp:
		return err
	case <-timer.C:
		return fmt.Errorf("audit: flush: deadline waiting for commit")
	}
}

// Close flushes, stops the writer, and releases the overflow file.
// The caller must still Close the Store to seal the session.
func (l *Logger) Close() error {
	close(l.done)
	l.wg.Wait()
	if l.overflow != nil {
		_ = l.overflow.Close()
	}
	return nil
}
