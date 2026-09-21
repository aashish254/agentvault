package audit

import (
	"encoding/json"
	"time"

	"github.com/aashish/agentvault/internal/event"
)

// Record is one auditable unit: the event, the policy verdict, and the
// final decision after any approval resolution.
type Record struct {
	Event    event.Event     `json:"event"`
	Verdict  event.Verdict   `json:"verdict"`
	Decision *event.Decision `json:"decision,omitempty"`
	LoggedAt time.Time       `json:"logged_at"`
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func event2Verdict(effect, ruleName string, evalMicros int64) event.Verdict {
	return event.Verdict{
		Effect:     event.Effect(effect),
		RuleName:   ruleName,
		EvalMicros: evalMicros,
	}
}

func decisionOf(finalEffect, approvedBy string, waitMs int64) *event.Decision {
	return &event.Decision{
		FinalEffect: event.Effect(finalEffect),
		ApprovedBy:  approvedBy,
		Waited:      time.Duration(waitMs) * time.Millisecond,
	}
}
