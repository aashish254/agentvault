package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, no CGO: driver name "sqlite"
)

// Store is the SQLite-backed audit database. One Store serves one
// process; internally a single writer goroutine (see logger.go) owns
// the chain state, so no locking is needed on the hot path.
type Store struct {
	db      *sql.DB
	path    string
	session *openSession
}

type openSession struct {
	id    string
	chain *chain
}

// Open creates/migrates the database at path (parent dirs 0700, file 0600).
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: mkdir: %w", err)
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: open: %w", err)
	}
	// Single connection: WAL + one writer goroutine means no contention.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schemaDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: migrate: %w", err)
	}
	if _, err := db.Exec(recordMigration); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: record migration: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	return &Store{db: db, path: path}, nil
}

// Path returns the database file location.
func (s *Store) Path() string { return s.path }

// BeginSession registers a new supervised session and starts its chain.
func (s *Store) BeginSession(id, agentName string, command []string, policyRaw []byte) error {
	if s.session != nil {
		return fmt.Errorf("audit: session %s already open", s.session.id)
	}
	c, err := newChain()
	if err != nil {
		return err
	}
	cmdJSON, _ := json.Marshal(command)
	_, err = s.db.Exec(
		`INSERT INTO sessions(id, started_at, agent_name, agent_command, policy_hash, pubkey)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, time.Now().UTC().Format(time.RFC3339Nano), agentName, string(cmdJSON),
		policyHashOf(policyRaw), c.pub,
	)
	if err != nil {
		return fmt.Errorf("audit: begin session: %w", err)
	}
	s.session = &openSession{id: id, chain: c}
	return nil
}

// Insert appends one event to the open session's chain.
// MUST be called from the single writer goroutine only.
func (s *Store) Insert(rec Record) error {
	if s.session == nil {
		return fmt.Errorf("audit: no open session")
	}
	e, v, d := rec.Event, rec.Verdict, rec.Decision
	ts := e.Timestamp.UTC().Format(time.RFC3339Nano)
	seq, prev, row := s.session.chain.append(e.CanonicalJSON(), string(v.Effect), v.RuleName, ts)

	var finalEffect, approvedBy string
	var waitMs int64
	if d != nil {
		finalEffect = string(d.FinalEffect)
		approvedBy = d.ApprovedBy
		waitMs = d.Waited.Milliseconds()
	}
	_, err := s.db.Exec(
		`INSERT INTO events(id, session_id, ts, seq, source, action, payload,
		                    rule_name, verdict, final_effect, approved_by, wait_ms,
		                    eval_micros, prev_hash, row_hash)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, s.session.id, ts, seq, string(e.Source), string(e.Action),
		string(e.CanonicalJSON()), v.RuleName, string(v.Effect),
		finalEffect, approvedBy, waitMs, v.EvalMicros, prev, row,
	)
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	return nil
}

// InsertBatch inserts records in one transaction (the logger's flush path).
func (s *Store) InsertBatch(recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO events(id, session_id, ts, seq, source, action, payload,
		                    rule_name, verdict, final_effect, approved_by, wait_ms,
		                    eval_micros, prev_hash, row_hash)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, rec := range recs {
		e, v, d := rec.Event, rec.Verdict, rec.Decision
		ts := e.Timestamp.UTC().Format(time.RFC3339Nano)
		seq, prev, row := s.session.chain.append(e.CanonicalJSON(), string(v.Effect), v.RuleName, ts)
		var finalEffect, approvedBy string
		var waitMs int64
		if d != nil {
			finalEffect = string(d.FinalEffect)
			approvedBy = d.ApprovedBy
			waitMs = d.Waited.Milliseconds()
		}
		if _, err := stmt.Exec(e.ID, s.session.id, ts, seq, string(e.Source),
			string(e.Action), string(e.CanonicalJSON()), v.RuleName,
			string(v.Effect), finalEffect, approvedBy, waitMs,
			v.EvalMicros, prev, row); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("audit: batch insert: %w", err)
		}
	}
	return tx.Commit()
}
