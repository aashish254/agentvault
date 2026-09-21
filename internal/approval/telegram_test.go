package approval

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var bg = context.Background()

// tgMock fakes the Telegram Bot API: records sendMessage, answers
// getUpdates with a scripted callback when armed, tracks edits.
// callback/messageID/chatID are goroutine-shared → behind mu.
type tgMock struct {
	t         *testing.T
	sent      atomic.Int32
	answered  atomic.Int32
	edited    atomic.Int32
	mu        sync.Mutex
	callback  string // when non-empty, next getUpdates returns this callback_data
	chatID    int64
	messageID int
}

func (m *tgMock) arm(callbackData string) {
	m.mu.Lock()
	m.callback = callbackData
	m.mu.Unlock()
}

func (m *tgMock) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")

		switch method {
		case "sendMessage":
			m.sent.Add(1)
			m.messageID = 4242
			kb, _ := json.Marshal(body["reply_markup"])
			if !strings.Contains(string(kb), "av:") {
				m.t.Error("sendMessage missing inline keyboard callback data")
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":4242}}`))
		case "getUpdates":
			m.mu.Lock()
			cb, chat := m.callback, m.chatID
			if cb != "" {
				m.callback = "" // deliver once
			}
			m.mu.Unlock()
			if cb != "" {
				resp := map[string]any{
					"ok": true,
					"result": []map[string]any{{
						"update_id": 1,
						"callback_query": map[string]any{
							"id":   "cbq1",
							"data": cb,
							"message": map[string]any{
								"message_id": 4242,
								"chat":       map[string]any{"id": chat},
							},
						},
					}},
				}
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
		case "answerCallbackQuery":
			m.answered.Add(1)
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		case "editMessageText":
			m.edited.Add(1)
			_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
		default:
			_, _ = w.Write([]byte(`{"ok":false,"description":"unknown method"}`))
		}
	}
}

func telegramEvent() Request {
	return Request{
		Event:     testEvent("git"),
		RuleName:  "git-push-ask",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}
}

func TestTelegramApproveFlow(t *testing.T) {
	mock := &tgMock{t: t, chatID: 123}
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	ch := NewTelegram("test-token", 123, srv.URL)
	defer ch.Close()

	respCh, err := ch.Ask(bg, telegramEvent())
	if err != nil {
		t.Fatal(err)
	}
	if mock.sent.Load() != 1 {
		t.Fatal("approval card not sent")
	}
	// Extract the event id from the waiters map to arm the mock callback.
	ch.mu.Lock()
	var eventID string
	for id := range ch.waiters {
		eventID = id
	}
	ch.mu.Unlock()
	mock.arm("av:" + eventID + ":rule")

	select {
	case resp := <-respCh:
		if !resp.Allow || !resp.AllowRule || resp.By != "telegram:123" {
			t.Fatalf("bad response: %+v", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no response from telegram channel")
	}
	if mock.answered.Load() != 1 {
		t.Fatal("callback query was never answered")
	}
	// Resolution broadcast edits the card.
	ch.NotifyResolved(eventID, "approved (rule memoized) by telegram:123")
	if mock.edited.Load() != 1 {
		t.Fatal("card not edited on resolution")
	}
}

func TestTelegramIgnoresWrongChat(t *testing.T) {
	mock := &tgMock{t: t, chatID: 999} // attacker chat
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	ch := NewTelegram("test-token", 123, srv.URL) // legit chat is 123
	defer ch.Close()

	respCh, err := ch.Ask(bg, telegramEvent())
	if err != nil {
		t.Fatal(err)
	}
	ch.mu.Lock()
	var eventID string
	for id := range ch.waiters {
		eventID = id
	}
	ch.mu.Unlock()
	mock.arm("av:" + eventID + ":once")

	select {
	case resp := <-respCh:
		t.Fatalf("attacker chat must be ignored, got %+v", resp)
	case <-time.After(1500 * time.Millisecond):
		// correct: silence
	}
}

func TestTelegramAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"description":"unauthorized"}`))
	}))
	defer srv.Close()
	ch := NewTelegram("bad-token", 123, srv.URL)
	defer ch.Close()
	if _, err := ch.Ask(bg, telegramEvent()); err == nil {
		t.Fatal("expected API error to propagate")
	}
}
