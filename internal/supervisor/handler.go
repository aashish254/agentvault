package supervisor

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"

	"github.com/aashish/agentvault/internal/event"
)

// handleRequest serves one connection: one request, one response.
// requestToken is the expected token ("" on unix, where the socket's
// file permissions are the auth boundary). Malformed requests and bad
// tokens get silence — callers fail closed.
func handleRequest(conn net.Conn, s *Supervisor, requestToken string) {
	var raw json.RawMessage
	// Decode reads exactly one JSON value from the stream — io.ReadAll
	// would deadlock, since the client waits for our response before
	// closing its write side.
	if json.NewDecoder(conn).Decode(&raw) != nil {
		return
	}
	var head struct {
		Type  string `json:"type"`
		Token string `json:"token"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return
	}
	if requestToken != "" &&
		subtle.ConstantTimeCompare([]byte(head.Token), []byte(requestToken)) != 1 {
		return
	}
	switch head.Type {
	case "eval":
		var req event.EvalRequest
		if json.Unmarshal(raw, &req) != nil {
			return
		}
		v := s.Evaluate(req.Event)
		writeJSON(conn, event.EvalResponse{
			Type: "verdict", Effect: v.Effect, RuleName: v.RuleName, Message: v.Message,
		})
	case "approve.list":
		var pending []event.PendingInfo
		for _, r := range s.approvals.Pending() {
			pending = append(pending, event.PendingInfo{
				EventID: r.Event.ID, RuleName: r.RuleName,
				Summary: r.Summary(), ExpiresAt: r.ExpiresAt,
			})
		}
		writeJSON(conn, event.ApproveListResponse{Type: "approve.list", Pending: pending})
	case "approve.resolve":
		var req event.ApproveResolveRequest
		if json.Unmarshal(raw, &req) != nil {
			return
		}
		id, err := s.approvals.Resolve(req.EventID, req.Allow, "cli")
		if err != nil {
			writeJSON(conn, event.ApproveResolveResponse{Type: "approve.resolve", Error: err.Error()})
			return
		}
		writeJSON(conn, event.ApproveResolveResponse{Type: "approve.resolve", OK: true, EventID: id})
	}
	// Unknown types: silence.
}

func writeJSON(w io.Writer, v any) {
	_ = json.NewEncoder(w).Encode(v)
}
