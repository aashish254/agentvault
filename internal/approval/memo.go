package approval

import (
	"sync"

	"github.com/aashish/agentvault/internal/event"
)

// memoKey identifies a memoized "allow this rule" decision: same rule,
// same action type, same normalized target.
func memoKey(ruleName string, e event.Event) string {
	target := e.Raw
	if e.Path != "" {
		target = e.Path
	}
	if e.Host != "" {
		target = e.Host
	}
	return ruleName + "|" + string(e.Action) + "|" + target
}

// memoCache is a bounded session-scoped set of memoized approvals.
// FIFO eviction at capacity (sufficient: memo churn is tiny).
type memoCache struct {
	mu    sync.Mutex
	set   map[string]struct{}
	order []string
	cap   int
}

func newMemoCache(cap int) *memoCache {
	return &memoCache{set: make(map[string]struct{}, cap), cap: cap}
}

func (m *memoCache) hit(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.set[key]
	return ok
}

func (m *memoCache) store(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.set[key]; ok {
		return
	}
	if len(m.order) >= m.cap {
		delete(m.set, m.order[0])
		m.order = m.order[1:]
	}
	m.set[key] = struct{}{}
	m.order = append(m.order, key)
}
