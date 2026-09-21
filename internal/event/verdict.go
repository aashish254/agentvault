package event

import "time"

// Effect is the verdict vocabulary. It mirrors config.Effect and is
// duplicated deliberately to avoid an import cycle (config imports nothing,
// event imports nothing, policy imports both).
type Effect string

const (
	Allow           Effect = "allow"
	Deny            Effect = "deny"
	RequireApproval Effect = "require_approval"
)

// Verdict is the policy engine's answer for one event.
type Verdict struct {
	Effect     Effect `json:"effect"`
	RuleName   string `json:"rule_name,omitempty"` // "" when the default fired
	Message    string `json:"message,omitempty"`   // human-facing reason
	EvalMicros int64  `json:"eval_micros"`         // policy eval latency
}

// Decision records the final outcome after any approval resolution.
type Decision struct {
	EventID     string        `json:"event_id"`
	FinalEffect Effect        `json:"final_effect"`          // after approval resolution
	ApprovedBy  string        `json:"approved_by,omitempty"` // "telegram:<chat_id>" | "tty" | ""
	Waited      time.Duration `json:"waited,omitempty"`
	TimedOut    bool          `json:"timed_out,omitempty"`
}
