package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Retain enforces audit.retention_days (SPEC §4.5): sessions that ended
// before the cutoff AND whose chain verifies are exported to
// <dbdir>/archive/<session>.jsonl (including the head signature), then
// their rows are deleted. Sessions that FAIL verification are never
// deleted — tampered evidence stays put and is reported.
//
// Deleting a whole session is chain-safe because chains are per-session
// (genesis prev_hash), so other sessions are unaffected.
func (s *Store) Retain(days int) (archived int, warnings []error, err error) {
	if days <= 0 {
		return 0, nil, nil // 0 = keep forever
	}
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339Nano)

	rows, err := s.db.Query(`SELECT id FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?`, cutoff)
	if err != nil {
		return 0, nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return 0, nil, err
		}
		ids = append(ids, id)
	}
	_ = rows.Close()

	for _, id := range ids {
		if verr := s.Verify(id); verr != nil {
			warnings = append(warnings, fmt.Errorf("retention: session %s failed verify, kept for forensics: %w", id, verr))
			continue
		}
		if err := s.archiveSession(id); err != nil {
			warnings = append(warnings, fmt.Errorf("retention: archive %s: %w", id, err))
			continue
		}
		if _, err := s.db.Exec(`DELETE FROM events WHERE session_id=?`, id); err != nil {
			return archived, warnings, err
		}
		if _, err := s.db.Exec(`DELETE FROM sessions WHERE id=?`, id); err != nil {
			return archived, warnings, err
		}
		archived++
	}
	return archived, warnings, nil
}

// archiveSession writes <dbdir>/archive/<id>.jsonl: a header line with
// the session metadata + signature, then one JSON record per event.
func (s *Store) archiveSession(id string) error {
	dir := filepath.Join(filepath.Dir(s.path), "archive")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var startedAt, agentName, agentCmd, policyHash string
	var pubkey, headHash, headSig []byte
	var endedAt sql.NullString
	err := s.db.QueryRow(
		`SELECT started_at, ended_at, agent_name, agent_command, policy_hash, pubkey, head_hash, head_sig
		 FROM sessions WHERE id=?`, id).
		Scan(&startedAt, &endedAt, &agentName, &agentCmd, &policyHash, &pubkey, &headHash, &headSig)
	if err != nil {
		return err
	}
	recs, err := s.Query(QueryOpts{SessionID: id})
	if err != nil {
		return err
	}
	// #nosec G304 -- path derives from the vault dir, not user input.
	f, err := os.OpenFile(filepath.Join(dir, id+".jsonl"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	header := map[string]any{
		"type": "agentvault-archive-header", "session_id": id,
		"started_at": startedAt, "ended_at": endedAt.String,
		"agent_name": agentName, "agent_command": json.RawMessage(agentCmd),
		"policy_hash": policyHash,
		"pubkey":      fmt.Sprintf("%x", pubkey), "head_hash": fmt.Sprintf("%x", headHash),
		"head_sig": fmt.Sprintf("%x", headSig),
	}
	enc := json.NewEncoder(f)
	if err := enc.Encode(header); err != nil {
		return err
	}
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
