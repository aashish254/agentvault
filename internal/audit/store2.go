package audit

import (
	"database/sql"
	"fmt"
	"time"
)

// SignAndClose seals the open session: signs the chain head, records it,
// destroys the private key, and marks the session ended.
func (s *Store) SignAndClose() error {
	if s.session == nil {
		return nil
	}
	head := s.session.chain.head()
	sig := s.session.chain.sign()
	pub := s.session.chain.pub
	_, err := s.db.Exec(
		`UPDATE sessions SET ended_at=?, head_hash=?, head_sig=? WHERE id=?`,
		time.Now().UTC().Format(time.RFC3339Nano), head, sig, s.session.id,
	)
	s.session.chain.destroy()
	s.session = nil
	if err != nil {
		return fmt.Errorf("audit: sign session: %w", err)
	}
	_ = pub // pubkey already stored at BeginSession
	return nil
}

// Close seals any open session and closes the database.
func (s *Store) Close() error {
	_ = s.SignAndClose()
	return s.db.Close()
}

// Verify recomputes a session's chain and validates its signature.
// Returns nil when intact; a descriptive error naming the first bad seq
// when tampered.
func (s *Store) Verify(sessionID string) error {
	var pubkey, headHash, headSig []byte
	var endedAt sql.NullString
	err := s.db.QueryRow(
		`SELECT pubkey, head_hash, head_sig, ended_at FROM sessions WHERE id=?`,
		sessionID).Scan(&pubkey, &headHash, &headSig, &endedAt)
	if err == sql.ErrNoRows {
		return fmt.Errorf("verify: session %q not found", sessionID)
	}
	if err != nil {
		return err
	}

	rows, err := s.db.Query(
		`SELECT id, seq, ts, payload, verdict, rule_name, prev_hash, row_hash
		 FROM events WHERE session_id=? ORDER BY seq ASC`, sessionID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	var stored []storedRow
	var lastSeq int64 = -1
	for rows.Next() {
		var r storedRow
		if err := rows.Scan(&r.id, &r.seq, &r.ts, &r.payload, &r.verdict,
			&r.ruleName, &r.prevHash, &r.rowHash); err != nil {
			return err
		}
		if r.seq != lastSeq+1 {
			return fmt.Errorf("verify: gap at seq %d (after %d) — rows deleted", r.seq, lastSeq)
		}
		lastSeq = r.seq
		stored = append(stored, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	head, err := recompute(stored)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if !endedAt.Valid || len(headHash) == 0 {
		return &UnsealedError{SessionID: sessionID, LastSeq: lastSeq}
	}
	if !equalBytes(head, headHash) {
		return fmt.Errorf("verify: chain head mismatch — trailing rows were deleted or altered")
	}
	if !verifySignature(pubkey, headHash, headSig) {
		return fmt.Errorf("verify: head signature invalid — session was re-signed by someone else")
	}
	return nil
}

// ErrUnsealed marks a session that was never sealed (crash/kill) but
// whose chain is intact — NOT tampering, just unsigned. Callers (CLI)
// render it as a warning, not a tamper alarm.
var ErrUnsealed = fmt.Errorf("session never sealed (crashed or killed); chain intact but unsigned")

// UnsealedError wraps ErrUnsealed with detail.
type UnsealedError struct {
	SessionID string
	LastSeq   int64
}

func (e *UnsealedError) Error() string {
	return fmt.Sprintf("%s: %s (intact to seq %d)", ErrUnsealed, e.SessionID, e.LastSeq)
}
func (e *UnsealedError) Unwrap() error { return ErrUnsealed }

type QueryOpts struct {
	SessionID string
	Verdict   string // "allow" | "deny" | "require_approval" | ""
	Action    string // e.g. "shell.exec" | ""
	Since     time.Duration
	Limit     int
}

// Query reads events back for `agentvault log --export`.
func (s *Store) Query(o QueryOpts) ([]Record, error) {
	q := `SELECT payload, verdict, rule_name, final_effect, approved_by, wait_ms, eval_micros
	      FROM events WHERE 1=1`
	var args []any
	if o.SessionID != "" {
		q += ` AND session_id=?`
		args = append(args, o.SessionID)
	}
	if o.Verdict != "" {
		q += ` AND verdict=?`
		args = append(args, o.Verdict)
	}
	if o.Action != "" {
		q += ` AND action=?`
		args = append(args, o.Action)
	}
	if o.Since > 0 {
		q += ` AND ts>=?`
		args = append(args, time.Now().UTC().Add(-o.Since).Format(time.RFC3339Nano))
	}
	q += ` ORDER BY ts ASC`
	if o.Limit > 0 {
		// #nosec G202 -- o.Limit is an int, not user-controlled text.
		q += fmt.Sprintf(` LIMIT %d`, o.Limit)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []Record
	for rows.Next() {
		var payload, verdict, ruleName, finalEffect, approvedBy string
		var waitMs, evalMicros int64
		if err := rows.Scan(&payload, &verdict, &ruleName, &finalEffect,
			&approvedBy, &waitMs, &evalMicros); err != nil {
			return nil, err
		}
		rec := Record{}
		if err := jsonUnmarshal([]byte(payload), &rec.Event); err != nil {
			return nil, fmt.Errorf("audit: corrupt payload: %w", err)
		}
		rec.Verdict = event2Verdict(verdict, ruleName, evalMicros)
		if finalEffect != "" {
			rec.Decision = decisionOf(finalEffect, approvedBy, waitMs)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Sessions lists known session ids, newest first.
func (s *Store) Sessions() ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM sessions ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
