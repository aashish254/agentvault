package event

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
