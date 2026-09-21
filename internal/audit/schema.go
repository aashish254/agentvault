package audit

// DDL from SPEC §3.4. Per-session hash chains: each session's first row
// uses the genesis hash, so archiving/deleting a whole session never
// breaks other sessions' chains.
const schemaDDL = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = FULL;

CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    started_at    TEXT NOT NULL,
    ended_at      TEXT,
    agent_name    TEXT NOT NULL,
    agent_command TEXT NOT NULL,
    policy_hash   TEXT NOT NULL,
    pubkey        BLOB,
    head_hash     BLOB,
    head_sig      BLOB
);

CREATE TABLE IF NOT EXISTS events (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES sessions(id),
    ts            TEXT NOT NULL,
    seq           INTEGER NOT NULL,
    source        TEXT NOT NULL,
    action        TEXT NOT NULL,
    payload       TEXT NOT NULL,
    rule_name     TEXT,
    verdict       TEXT NOT NULL,
    final_effect  TEXT,
    approved_by   TEXT,
    wait_ms       INTEGER,
    eval_micros   INTEGER,
    prev_hash     BLOB NOT NULL,
    row_hash      BLOB NOT NULL,
    UNIQUE(session_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);
CREATE INDEX IF NOT EXISTS idx_events_action  ON events(action);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
`

const recordMigration = `
INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ','now'));
`
