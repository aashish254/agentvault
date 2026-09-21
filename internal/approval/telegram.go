package approval

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// TelegramChannel pages approvals via Bot API long polling with inline
// keyboards. baseURL is injectable so tests run against httptest mocks.
// Only the configured chatID may answer; everything else is logged as
// suspicious and ignored (SPEC §4.4).
type TelegramChannel struct {
	token   string
	chatID  int64
	baseURL string
	client  *http.Client

	mu      sync.Mutex
	waiters map[string]chan Response // eventID → response chan
	msgs    map[string]int           // eventID → telegram message_id
	offset  int64
	stop    chan struct{}
	stopped sync.Once
}

// NewTelegram starts polling immediately. baseURL="" = production API.
func NewTelegram(token string, chatID int64, baseURL string) *TelegramChannel {
	if baseURL == "" {
		baseURL = "https://api.telegram.org"
	}
	t := &TelegramChannel{
		token: token, chatID: chatID, baseURL: baseURL,
		client:  &http.Client{Timeout: 35 * time.Second},
		waiters: map[string]chan Response{},
		msgs:    map[string]int{},
		stop:    make(chan struct{}),
	}
	go t.pollLoop()
	return t
}

func (t *TelegramChannel) Name() string { return "telegram" }

// Close stops the poll loop.
func (t *TelegramChannel) Close() {
	t.stopped.Do(func() { close(t.stop) })
}

// Ask sends the approval card with inline buttons and returns the
// channel that receives the tap.
func (t *TelegramChannel) Ask(ctx Context, r Request) (<-chan Response, error) {
	resp := make(chan Response, 1)
	t.mu.Lock()
	t.waiters[r.Event.ID] = resp
	t.mu.Unlock()

	text := fmt.Sprintf("🛡 *AgentVault — approval requested*\nRule: `%s`\n```\n%s\n```\ncwd: `%s`\nexpires: %s",
		r.RuleName, r.Summary(), r.Event.Cwd, r.ExpiresAt.Format("15:04:05"))
	keyboard := map[string]any{
		"inline_keyboard": [][]map[string]string{{
			{"text": "✅ Allow once", "callback_data": "av:" + r.Event.ID + ":once"},
			{"text": "🔁 Allow rule", "callback_data": "av:" + r.Event.ID + ":rule"},
			{"text": "❌ Deny", "callback_data": "av:" + r.Event.ID + ":deny"},
		}},
	}
	msgID, err := t.sendMessage(text, keyboard)
	if err != nil {
		t.mu.Lock()
		delete(t.waiters, r.Event.ID)
		t.mu.Unlock()
		return nil, err
	}
	t.mu.Lock()
	t.msgs[r.Event.ID] = msgID
	t.mu.Unlock()
	return resp, nil
}

// NotifyResolved edits the card so all devices see the outcome.
func (t *TelegramChannel) NotifyResolved(eventID string, outcome string) {
	t.mu.Lock()
	msgID, ok := t.msgs[eventID]
	t.mu.Unlock()
	if !ok {
		return
	}
	_ = t.editMessage(msgID, fmt.Sprintf("🛡 AgentVault request %s\n→ *%s*", shortID(eventID), outcome))
}
