package approval

// Telegram Bot API plumbing: poll loop, callback dispatch, and the three
// API calls (sendMessage, editMessageText, answerCallbackQuery).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type tgUpdate struct {
	UpdateID      int64 `json:"update_id"`
	CallbackQuery *struct {
		ID      string `json:"id"`
		Data    string `json:"data"`
		Message struct {
			MessageID int `json:"message_id"`
			Chat      struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
	} `json:"callback_query"`
}

func (t *TelegramChannel) pollLoop() {
	for {
		select {
		case <-t.stop:
			return
		default:
		}
		updates, err := t.getUpdates(t.offset)
		if err != nil {
			select {
			case <-t.stop:
				return
			case <-time.After(3 * time.Second): // backoff on API failure
			}
			continue
		}
		for _, u := range updates {
			if u.UpdateID >= t.offset {
				t.offset = u.UpdateID + 1
			}
			t.handleUpdate(u)
		}
	}
}

func (t *TelegramChannel) handleUpdate(u tgUpdate) {
	cb := u.CallbackQuery
	if cb == nil || !strings.HasPrefix(cb.Data, "av:") {
		return
	}
	_ = t.answerCallback(cb.ID) // stop the client's loading spinner
	if cb.Message.Chat.ID != t.chatID {
		return // not our human; silently ignore (SPEC §4.4)
	}
	parts := strings.Split(cb.Data, ":")
	if len(parts) != 3 {
		return
	}
	eventID, action := parts[1], parts[2]

	t.mu.Lock()
	resp, ok := t.waiters[eventID]
	t.mu.Unlock()
	if !ok {
		return // already resolved or unknown
	}
	switch action {
	case "once":
		resp <- Response{Allow: true, By: "telegram:" + strconv.FormatInt(t.chatID, 10)}
	case "rule":
		resp <- Response{Allow: true, AllowRule: true, By: "telegram:" + strconv.FormatInt(t.chatID, 10)}
	case "deny":
		resp <- Response{Allow: false, By: "telegram:" + strconv.FormatInt(t.chatID, 10)}
	}
}

// --- API calls ---

func (t *TelegramChannel) apiCall(method string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := t.baseURL + "/bot" + t.token + "/" + method
	resp, err := t.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var envelope struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("telegram %s: bad response: %w", method, err)
	}
	if !envelope.OK {
		return fmt.Errorf("telegram %s: %s", method, envelope.Description)
	}
	if out != nil && len(envelope.Result) > 0 {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}

func (t *TelegramChannel) sendMessage(text string, keyboard map[string]any) (int, error) {
	var result struct {
		MessageID int `json:"message_id"`
	}
	err := t.apiCall("sendMessage", map[string]any{
		"chat_id":      t.chatID,
		"text":         text,
		"parse_mode":   "Markdown",
		"reply_markup": keyboard,
	}, &result)
	return result.MessageID, err
}

func (t *TelegramChannel) editMessage(messageID int, text string) error {
	return t.apiCall("editMessageText", map[string]any{
		"chat_id": t.chatID, "message_id": messageID,
		"text": text, "parse_mode": "Markdown",
	}, nil)
}

func (t *TelegramChannel) answerCallback(id string) error {
	return t.apiCall("answerCallbackQuery", map[string]any{"callback_query_id": id}, nil)
}

func (t *TelegramChannel) getUpdates(offset int64) ([]tgUpdate, error) {
	var updates []tgUpdate
	err := t.apiCall("getUpdates", map[string]any{
		"offset": offset, "timeout": 30, "allowed_updates": []string{"callback_query"},
	}, &updates)
	return updates, err
}
