package event

import "time"

// Wire protocol between shims and the supervisor (SPEC §3.3).
// JSON lines over the session IPC channel. Shared by both packages so
// the encoding can never drift.

// EvalRequest is sent by a shim for every intercepted action.
type EvalRequest struct {
	Type  string `json:"type"`  // always "eval"
	Token string `json:"token"` // session auth token (empty on unix-socket platforms)
	Event Event  `json:"event"`
}

// EvalResponse is the supervisor's answer.
type EvalResponse struct {
	Type     string `json:"type"` // always "verdict"
	Effect   Effect `json:"effect"`
	RuleName string `json:"rule_name,omitempty"`
	Message  string `json:"message,omitempty"`
}

// ApproveListRequest asks for the pending approvals of a session.
type ApproveListRequest struct {
	Type  string `json:"type"` // always "approve.list"
	Token string `json:"token"`
}

// PendingInfo describes one pending approval to a remote CLI.
type PendingInfo struct {
	EventID   string    `json:"event_id"`
	RuleName  string    `json:"rule_name"`
	Summary   string    `json:"summary"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ApproveListResponse carries the pending list.
type ApproveListResponse struct {
	Type    string        `json:"type"` // always "approve.list"
	Pending []PendingInfo `json:"pending"`
}

// ApproveResolveRequest resolves one pending approval.
type ApproveResolveRequest struct {
	Type    string `json:"type"` // always "approve.resolve"
	Token   string `json:"token"`
	EventID string `json:"event_id"` // full id or unique ≥6-char prefix
	Allow   bool   `json:"allow"`
}

// ApproveResolveResponse confirms or explains failure.
type ApproveResolveResponse struct {
	Type    string `json:"type"` // always "approve.resolve"
	OK      bool   `json:"ok"`
	EventID string `json:"event_id,omitempty"`
	Error   string `json:"error,omitempty"`
}
