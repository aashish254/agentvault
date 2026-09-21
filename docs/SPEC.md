# AgentVault — Production Specification (v0.1.0)

> Runtime security layer and permission firewall for autonomous AI agents.
> Owner: solo build. Stack: Go 1.23+, CEL (cel-go), SQLite (modernc.org/sqlite), Telegram Bot API, BubbleTea TUI, Cobra CLI.

**Document status:** Normative. If code and this document disagree during v0.1, fix the code or amend this document in the same commit.

---

## Table of Contents

1. End-to-End System Architecture
2. Complete Directory Structure
3. Core Data Structures & Schemas
4. Module-by-Module Implementation Blueprint
5. 8-Week Execution Roadmap (granular)
6. Testing Strategy
7. Risk Register & Non-Goals

---

## 1. End-to-End System Architecture

### 1.1 Design Principles

1. **Fail closed.** Any error in policy evaluation, approval delivery, or the audit pipeline results in DENY, never silent allow.
2. **Single binary.** `agentvault` is one static binary. Shims, the MCP proxy, the egress proxy, the approval daemon, and the TUI are all subcommands of the same binary.
3. **Local-first.** No telemetry, no phone-home, no required network dependency. Telegram is optional; TTY prompt is the offline fallback.
4. **Honest enforcement.** v0.1 is *guardrails + tamper-evident audit*, not a kernel sandbox. Shims and proxies can be bypassed by a sufficiently adversarial agent; kernel-level confinement (macOS Seatbelt / Linux Landlock) is Phase 2 (§7). The README must say this plainly — honesty is a feature, not a weakness.

### 1.2 Interception Channels

An agent (OpenCode, OpenClaw, a shell script, anything) acts on the world through exactly four channels. AgentVault v0.1 covers all four:

| # | Channel | Mechanism | Fidelity | Known limitation |
|---|---------|-----------|----------|------------------|
| 1 | **MCP tool calls** | AgentVault poses as the MCP server over stdio and proxies to the real server. Intercepts every `tools/call` JSON-RPC message. | Full args, tool name, structured | Only covers tools routed through MCP |
| 2 | **Shell commands** | `~/.agentvault/shims/` is prepended to `PATH`. Shims for dangerous binaries (`rm`, `curl`, `wget`, `ssh`, `git`, …) are symlinks to `agentvault __shim <name>`, which evaluates policy then `exec`s the real binary. | argv, cwd, env | Agent can call the real binary by absolute path (Phase 2 sandbox closes this) |
| 3 | **Network egress** | Child env gets `HTTP_PROXY`/`HTTPS_PROXY` pointing at a local CONNECT proxy on `127.0.0.1:<random>`. Allow/deny by domain:port. | domain, port | Honors only proxy-aware clients; TLS content not inspected in v0.1 |
| 4 | **Filesystem** | v0.1: covered indirectly — MCP `fs.*` tools via channel 1, shell commands via channel 2. Phase 2: Seatbelt/Landlock profiles generated from the same policy YAML. | path, op | No direct syscall interception in v0.1 |

### 1.3 Component Diagram

```
                            ┌────────────────────────────────────────────┐
                            │              agentvault run                │
                            │            (supervisor process)            │
                            │                                            │
                            │  ┌────────────┐   ┌─────────────────────┐  │
                            │  │  Policy    │   │   Audit Logger      │  │
                            │  │  Evaluator │──▶│  (hash-chain →      │  │
                            │  │  (CEL)     │   │   SQLite + SIG)     │  │
                            │  └─────▲──────┘   └─────────▲───────────┘  │
                            │        │                    │              │
                            │  ┌─────┴──────┐   ┌─────────┴───────────┐  │
                            │  │ Approval   │   │  Egress Proxy       │  │
                            │  │ Daemon     │   │  (CONNECT, 127.0.0.1)│  │
                            │  │ (Telegram/ │   └─────────▲───────────┘  │
                            │  │  TTY)      │             │ HTTP_PROXY   │
                            │  └─────▲──────┘             │              │
                            └────────┼─────────────────────┼──────────────┘
              unix socket ~/.agentvault/run/<session>.sock│
                            │        │                    │
   ┌────────────────────────┼────────┼────────────────────┼───────────┐
   │                        │        │                    │           │
┌──┴─────────┐   ┌──────────┴───┐   │   ┌────────────────┴────┐      │
│ MCP proxy  │   │ PATH shims   │   │   │    CHILD PROCESS      │      │
│ (per MCP   │   │ rm/curl/ssh/ │   │   │    (e.g. opencode)    │      │
│ server)    │   │ git → __shim │───┼──▶│    env: PATH+shims,   │      │
└──┬─────────┘   └──────────────┘   │   │    HTTP(S)_PROXY      │      │
   │ stdio JSON-RPC                 │   └───────────────────────┘      │
   ▼                                 │           ▲ stdout/stderr passthrough
┌──────────────┐                     └───────────┼───────────────────────┘
│ real MCP     │                                 │
│ server       │◀───────── proxied ──────────────┘
└──────────────┘                        user's terminal
```

### 1.4 Event Dataflow (happy path)

1. `agentvault run -- opencode` parses `agentvault.yaml`, compiles CEL expressions once (fail fast on compile errors), opens/creates the audit DB, generates an ephemeral Ed25519 session keypair.
2. Supervisor starts: egress proxy listener, MCP proxy per configured server, approval daemon, and a unix socket at `~/.agentvault/run/<session_id>.sock` (mode 0600) for shim → supervisor IPC.
3. Child spawned with modified env: `PATH=~/.agentvault/shims:$PATH`, `HTTP(S)_PROXY=http://127.0.0.1:<port>`, `AGENTVAULT_SESSION=<id>`, `AGENTVAULT_SOCK=<path>`.
4. Any action on channels 1–3 produces an `InterceptedEvent` (§3.3) sent to the supervisor over the socket (shims) or in-process (MCP/egress).
5. Policy Evaluator returns `ALLOW | DENY | REQUIRE_APPROVAL` (+ which rule matched).
6. `ALLOW` → log async → execute. `DENY` → log → synthetic error returned to the agent ("blocked by AgentVault policy: <rule name>") — the agent sees a normal tool error and can adapt. `REQUIRE_APPROVAL` → log as pending → Approval Daemon → on response log decision → execute or reject.
7. Every audit row is hash-chained (`row_hash = SHA256(prev_row_hash || canonical_json)`) and the chain head is Ed25519-signed on session close. `agentvault verify` recomputes the chain.

### 1.5 Approval Flow (async, timeout-safe)

```
event(REQUIRE_APPROVAL)
  → daemon creates ApprovalRequest{id, event, expires_at = now + cfg.timeout}
  → dispatches to ALL configured channels concurrently:
      • Telegram: inline keyboard [✅ Allow once] [🔁 Allow rule] [❌ Deny]
      • TTY (if foreground): inline prompt, countdown
  → first decisive response wins; others receive "already resolved"
  → timeout or daemon unreachable → DENY (fail closed)
  → decision + responder + latency logged to audit DB
```

**"Allow rule"** writes a session-scoped memoized approval (never persisted to the YAML) so a build running 40 `npm` calls doesn't page the user 40 times. Memo key = `(rule_name, action_type, normalized_target)`.

---

## 2. Complete Directory Structure

```
agentvault/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                  # lint, test, race, cross-compile matrix
│   │   └── release.yml             # goreleaser on tag v*
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.yml
│       └── feature_request.yml
├── cmd/
│   └── agentvault/
│       └── main.go                 # os.Exit(cli.Execute()); nothing else
├── internal/
│   ├── cli/
│   │   ├── root.go                 # cobra root: --config --verbose --no-color
│   │   ├── run.go                  # `agentvault run -- <cmd>`
│   │   ├── log.go                  # `agentvault log` (TUI + --since/--export)
│   │   ├── init.go                 # `agentvault init` (wizard → agentvault.yaml)
│   │   ├── policy.go               # `agentvault policy check|test`
│   │   ├── verify.go               # `agentvault verify` (audit chain verification)
│   │   ├── approve.go              # `agentvault approve list|allow|deny`
│   │   ├── daemon.go               # `agentvault daemon` (systemd/launchd mode)
│   │   └── shim.go                 # hidden: `agentvault __shim <bin> [args...]`
│   ├── config/
│   │   ├── config.go               # Policy struct, Load(), Validate()
│   │   ├── config_test.go
│   │   └── defaults.go             # DefaultPolicy() — secure-by-default template
│   ├── event/
│   │   ├── event.go                # Event struct, ActionType, CanonicalJSON()
│   │   ├── event_test.go
│   │   └── verdict.go              # Verdict, RuleRef, Decision types
│   ├── policy/
│   │   ├── engine.go               # Engine iface: Evaluate(Event) → Verdict
│   │   ├── cel.go                  # cel-go compiler + evaluator
│   │   ├── cel_test.go
│   │   ├── matcher.go              # glob (paths), cmd (shell), cidr (net) helpers
│   │   └── testdata/               # .yaml policy fixtures + expected verdicts
│   ├── supervisor/
│   │   ├── supervisor.go           # orchestrates run: spawn, wait, cleanup
│   │   ├── child.go                # exec.Cmd env assembly, signal forwarding
│   │   ├── socket.go               # unix socket server for shim IPC
│   │   └── supervisor_test.go
│   ├── proxy/
│   │   ├── mcp/
│   │   │   ├── proxy.go            # stdio MCP proxy, JSON-RPC framing
│   │   │   ├── intercept.go        # tools/call interception point
│   │   │   └── proxy_test.go
│   │   └── egress/
│   │       ├── connect.go          # HTTP CONNECT proxy
│   │       ├── allowlist.go        # domain:port verdict lookup
│   │       └── connect_test.go
│   ├── shim/
│   │   ├── shim.go                 # __shim: build Event → RPC → exec/deny
│   │   ├── install.go              # writes ~/.agentvault/shims symlinks
│   │   └── shim_test.go
│   ├── approval/
│   │   ├── daemon.go               # request lifecycle, dedupe, memo cache
│   │   ├── telegram.go             # Bot API long-poll, inline keyboards
│   │   ├── telegram_test.go
│   │   ├── tty.go                  # interactive terminal fallback
│   │   └── daemon_test.go
│   ├── audit/
│   │   ├── logger.go               # write path, buffered, flush-on-signal
│   │   ├── store.go                # sqlite open, migrate, query
│   │   ├── chain.go                # sha256 hash chain + Ed25519 sign/verify
│   │   ├── schema.go               # DDL statements (§3.4)
│   │   └── audit_test.go
│   └── tui/
│       ├── logview.go              # BubbleTea model: filterable event table
│       ├── detail.go               # event detail pane (args, rule, timing)
│       ├── styles.go               # lipgloss theme
│       └── logview_test.go
├── pkg/                            # empty in v0.1 — no public API until stable
├── docs/
│   ├── SPEC.md                     # this file
│   ├── integrations/
│   │   ├── opencode.md
│   │   └── openclaw.md
│   └── img/
│       └── demo.gif                # THE gif — produced week 7
├── test/
│   ├── e2e/
│   │   ├── harness.go              # fake agent binary + scripted scenarios
│   │   ├── run_block_test.go       # rm -rf blocked end-to-end
│   │   ├── approval_test.go        # telegram-mock approve flow
│   │   └── mcp_test.go             # fake MCP server roundtrip
│   └── fixtures/
│       ├── fakeagent.sh            # scripted agent that attempts bad things
│       └── policies/
├── scripts/
│   ├── demo.sh                     # reproducible asciinema demo recording
│   └── install.sh                  # curl | sh installer (checksum-verified)
├── .goreleaser.yml                 # darwin/linux × amd64/arm64, brew tap
├── go.mod
├── go.sum
├── Makefile                        # build, test, lint, demo, release
├── README.md                       # hook + gif + install + quickstart
├── SECURITY.md                     # threat model + vuln disclosure
├── LICENSE                         # Apache-2.0
└── CONTRIBUTING.md
```

**Layout rationale:** everything under `internal/` means zero accidental public API in v0.1 — freedom to refactor without breaking importers. `main.go` is 3 lines; all wiring lives in `internal/cli`. Tests sit beside their package; cross-package scenarios live only in `test/e2e`.

---

## 3. Core Data Structures & Schemas

### 3.1 `agentvault.yaml` → Go structs (`internal/config/config.go`)

```yaml
# agentvault.yaml — complete annotated example
version: 1

agent:
  name: "opencode"                 # free-form label used in audit rows
  command: ["opencode"]            # filled by `run`, overridable here

defaults:                          # evaluated when no rule matches
  action: deny                     # allow | deny | require_approval  (RECOMMEND: deny)
  approval_timeout: 60s

budgets:
  daily_spend_usd: 2.00            # REQUIRE_APPROVAL beyond this (needs cost feed, §7)
  max_actions_per_minute: 120      # rate limit; excess → REQUIRE_APPROVAL

rules:                             # FIRST match wins, in document order
  - name: "protect-credentials"
    match:
      action: [fs.read, fs.write, fs.delete]
      path: ["~/.ssh/**", "~/.aws/**", "~/.config/gcloud/**"]
    effect: deny
    message: "Credential paths are off-limits to agents."

  - name: "block-destructive-shell"
    match:
      action: [shell.exec]
      cel: 'event.cmd in ["rm","dd","mkfs","shutdown","reboot"] ||
            event.argv.exists(a, a.startsWith("-rf")) ||
            event.raw.matches("\\| *sh\\b")'
    effect: deny

  - name: "workdir-is-free"
    match:
      action: [fs.read, fs.write]
      path: ["./**", "~/projects/**"]
    effect: allow

  - name: "net-egress-ask"
    match:
      action: [net.egress]
      not_host: ["api.anthropic.com", "api.openai.com", "*.githubusercontent.com"]
    effect: require_approval

  - name: "git-push-ask"
    match:
      action: [shell.exec]
      cel: 'event.cmd == "git" && event.argv.size() > 1 && event.argv[1] == "push"'
    effect: require_approval

approvals:
  timeout: 60s                     # per-request override of defaults.approval_timeout
  channels:
    telegram:
      enabled: true
      bot_token_env: AGENTVAULT_TELEGRAM_TOKEN   # never a literal secret
      chat_id_env: AGENTVAULT_TELEGRAM_CHAT_ID
    tty:
      enabled: true                # fallback when stdout is a terminal

mcp_servers:                       # wrapped MCP servers (channel 1)
  - name: filesystem
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
    tool_policies:                 # optional per-tool overrides
      - tool: "delete_file"
        effect: require_approval

shims:                             # channel 2
  binaries: [rm, curl, wget, ssh, scp, git, npm, npx, pip, brew, dd]

egress:                            # channel 3
  listen: "127.0.0.1:0"            # 0 = random port
  default: deny                    # deny | allow | require_approval
  allow_hosts: ["api.anthropic.com", "api.openai.com"]

audit:
  path: "~/.agentvault/audit.db"
  retention_days: 90               # 0 = keep forever
  sign_on_close: true
```

```go
// internal/config/config.go
package config

import "time"

type Policy struct {
	Version  int         `yaml:"version"`
	Agent    AgentCfg    `yaml:"agent"`
	Defaults DefaultsCfg `yaml:"defaults"`
	Budgets  BudgetsCfg  `yaml:"budgets"`
	Rules    []Rule      `yaml:"rules"`
	Approvals ApprovalsCfg `yaml:"approvals"`
	MCPServers []MCPServerCfg `yaml:"mcp_servers"`
	Shims    ShimsCfg    `yaml:"shims"`
	Egress   EgressCfg   `yaml:"egress"`
	Audit    AuditCfg    `yaml:"audit"`
}

type AgentCfg struct {
	Name    string   `yaml:"name"`
	Command []string `yaml:"command"`
}

type DefaultsCfg struct {
	Action          Effect        `yaml:"action"`
	ApprovalTimeout time.Duration `yaml:"approval_timeout"`
}

type BudgetsCfg struct {
	DailySpendUSD      float64 `yaml:"daily_spend_usd"`
	MaxActionsPerMinute int    `yaml:"max_actions_per_minute"`
}

// Effect is the outcome vocabulary shared by config, engine, and audit.
type Effect string
const (
	EffectAllow           Effect = "allow"
	EffectDeny            Effect = "deny"
	EffectRequireApproval Effect = "require_approval"
)

type Rule struct {
	Name    string  `yaml:"name"`
	Match   Match   `yaml:"match"`
	Effect  Effect  `yaml:"effect"`
	Message string  `yaml:"message,omitempty"`
}

// Match: all populated fields are ANDed. Within a list, OR.
// CEL (if non-empty) must also evaluate true.
type Match struct {
	Action  []ActionType `yaml:"action,omitempty"`
	Path    []string     `yaml:"path,omitempty"`      // glob, ~ expanded, ** supported
	Host    []string     `yaml:"host,omitempty"`      // exact or *.suffix
	NotHost []string     `yaml:"not_host,omitempty"`
	Tool    []string     `yaml:"tool,omitempty"`      // MCP tool names
	CEL     string       `yaml:"cel,omitempty"`       // arbitrary expression over event
}

type ApprovalsCfg struct {
	Timeout  time.Duration  `yaml:"timeout"`
	Channels ChannelsCfg    `yaml:"channels"`
}

type ChannelsCfg struct {
	Telegram TelegramCfg `yaml:"telegram"`
	TTY      TTYCfg      `yaml:"tty"`
}

type TelegramCfg struct {
	Enabled     bool   `yaml:"enabled"`
	BotTokenEnv string `yaml:"bot_token_env"`
	ChatIDEnv   string `yaml:"chat_id_env"`
}

type TTYCfg struct{ Enabled bool `yaml:"enabled"` }

type MCPServerCfg struct {
	Name         string        `yaml:"name"`
	Command      []string      `yaml:"command"`
	ToolPolicies []ToolPolicy  `yaml:"tool_policies,omitempty"`
}

type ToolPolicy struct {
	Tool   string `yaml:"tool"`
	Effect Effect `yaml:"effect"`
}

type ShimsCfg struct{ Binaries []string `yaml:"binaries"` }

type EgressCfg struct {
	Listen      string   `yaml:"listen"`
	Default     Effect   `yaml:"default"`
	AllowHosts  []string `yaml:"allow_hosts"`
}

type AuditCfg struct {
	Path          string `yaml:"path"`
	RetentionDays int    `yaml:"retention_days"`
	SignOnClose   bool   `yaml:"sign_on_close"`
}

// Load reads, expands ~ and $ENV, validates. Any error is fatal (fail closed).
func Load(path string) (*Policy, error)
// Validate catches: empty rules + default allow (warn), bad globs,
// CEL compile errors, unknown effects, missing env vars for telegram.
func (p *Policy) Validate() error
```

### 3.2 Event & Verdict structs (`internal/event/`)

```go
// internal/event/event.go
package event

import "time"

// ActionType is the normalized vocabulary across all 4 channels.
type ActionType string
const (
	ActionFSRead   ActionType = "fs.read"
	ActionFSWrite  ActionType = "fs.write"
	ActionFSDelete ActionType = "fs.delete"
	ActionShell    ActionType = "shell.exec"
	ActionNetEgress ActionType = "net.egress"
	ActionMCPTool  ActionType = "mcp.tool"
)

// Source identifies which interception channel produced the event.
type Source string
const (
	SourceMCP    Source = "mcp"
	SourceShim   Source = "shim"
	SourceEgress Source = "egress"
)

// Event is the single canonical payload every channel must build.
// Zero-valued optional fields are omitted from CanonicalJSON.
type Event struct {
	ID        string            `json:"id"`         // ULID, generated at interception
	SessionID string            `json:"session_id"`
	Timestamp time.Time         `json:"ts"`         // UTC, RFC3339Nano in JSON
	Source    Source            `json:"source"`
	Action    ActionType        `json:"action"`

	// shell.exec
	Cmd   string   `json:"cmd,omitempty"`   // basename: "rm"
	Argv  []string `json:"argv,omitempty"`
	Raw   string   `json:"raw,omitempty"`   // full joined command line

	// fs.* and mcp filesystem tools
	Path string `json:"path,omitempty"` // absolute, ~ expanded, symlink-resolved

	// net.egress
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`

	// mcp.tool
	Server   string          `json:"server,omitempty"`
	Tool     string          `json:"tool,omitempty"`
	ToolArgs json.RawMessage `json:"tool_args,omitempty"`

	Cwd     string            `json:"cwd"`
	Env     map[string]string `json:"-"` // NEVER serialized or logged (secret leakage)
	PID     int               `json:"pid"`
}

// CanonicalJSON returns deterministic JSON (sorted keys, no env) used
// for hashing into the audit chain. MUST NOT include Env.
func (e Event) CanonicalJSON() []byte

// internal/event/verdict.go
package event

import "time"

type Effect string // mirrors config.Effect; duplicated to avoid import cycle
const (
	Allow           Effect = "allow"
	Deny            Effect = "deny"
	RequireApproval Effect = "require_approval"
)

type Verdict struct {
	Effect    Effect  `json:"effect"`
	RuleName  string  `json:"rule_name,omitempty"`  // "" when default fired
	Message   string  `json:"message,omitempty"`    // human-facing reason
	EvalMicros int64  `json:"eval_micros"`          // policy eval latency
}

type Decision struct {
	EventID     string        `json:"event_id"`
	FinalEffect Effect        `json:"final_effect"` // after approval resolution
	ApprovedBy  string        `json:"approved_by,omitempty"` // "telegram:<chat_id>" | "tty" | ""
	Waited      time.Duration `json:"waited,omitempty"`
	TimedOut    bool          `json:"timed_out,omitempty"`
}
```

### 3.3 Shim → Supervisor wire protocol (`internal/supervisor/socket.go`)

Length-prefixed JSON over the session unix socket. One request/response per connection keeps the shim dead simple:

```json
// Request  (shim → supervisor)
{"type":"eval","event":{ /* Event */ }}
// Response (supervisor → shim)
{"type":"verdict","effect":"allow","rule_name":"workdir-is-free","message":""}
// On any socket/parse error the shim exits 77 with stderr:
// "agentvault: policy check failed — refusing to run <cmd> (fail closed)"
```

### 3.4 SQLite audit schema (`internal/audit/schema.go`)

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = FULL;   -- durability over speed; this is an audit log

CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,            -- ULID
    started_at    TEXT NOT NULL,               -- RFC3339Nano UTC
    ended_at      TEXT,
    agent_name    TEXT NOT NULL,
    agent_command TEXT NOT NULL,               -- JSON array
    policy_hash   TEXT NOT NULL,               -- sha256 of agentvault.yaml bytes
    pubkey        BLOB,                        -- Ed25519 session public key (32 B)
    head_hash     BLOB,                        -- final chain head
    head_sig      BLOB                         -- Ed25519 sig over head_hash
);

CREATE TABLE IF NOT EXISTS events (
    id            TEXT PRIMARY KEY,            -- ULID == Event.ID
    session_id    TEXT NOT NULL REFERENCES sessions(id),
    ts            TEXT NOT NULL,
    seq           INTEGER NOT NULL,            -- per-session monotonic
    source        TEXT NOT NULL,
    action        TEXT NOT NULL,
    payload       TEXT NOT NULL,               -- Event.CanonicalJSON()
    rule_name     TEXT,
    verdict       TEXT NOT NULL,               -- allow|deny|require_approval
    final_effect  TEXT,                        -- post-approval outcome
    approved_by   TEXT,
    wait_ms       INTEGER,
    eval_micros   INTEGER,
    prev_hash     BLOB NOT NULL,               -- 32 B; genesis = sha256("agentvault:v1")
    row_hash      BLOB NOT NULL,               -- sha256(prev_hash || payload || verdict || rule_name || ts)
    UNIQUE(session_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);
CREATE INDEX IF NOT EXISTS idx_events_action  ON events(action);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
INSERT INTO schema_migrations(version, applied_at) VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ','now'));
```

**Tamper-evidence guarantees:** deleting or editing any row breaks every subsequent `row_hash`; deleting a *suffix* of rows breaks `sessions.head_hash`; re-computing the whole chain is impossible without invalidating `head_sig` (session private key is destroyed at exit). `agentvault verify` walks the chain and reports the first divergent `seq`.

---

## 4. Module-by-Module Implementation Blueprint

### 4.1 CLI entrypoint (`cmd/agentvault/main.go`, `internal/cli/`)

Cobra-based. `main.go`:

```go
package main

import (
	"os"
	"github.com/YOURUSER/agentvault/internal/cli"
)

func main() { os.Exit(cli.Execute()) }
```

**Subcommands contract:**

| Command | Behavior | Exit codes |
|---|---|---|
| `run [flags] -- <cmd...>` | Load policy → start supervisor (§4.2) → spawn child → forward signals → on child exit: flush audit, sign chain, exit with child's code | child's code; `2` = policy load failure |
| `log [--since 24h] [--verdict deny] [--action shell.exec] [--session <id>] [--export json\|csv]` | No flags → BubbleTea TUI. With `--export` → stream to stdout (pipeable) | `0` |
| `init [--non-interactive]` | Wizard: detects installed agents (`opencode`, `claude` in PATH), asks which channels to protect, writes `agentvault.yaml`, installs shims, optionally walks Telegram bot setup (paste token → sends test message) | `0`, `1` user abort |
| `policy check` | Parse + compile everything; per-rule compile status; warn on shadowed rules (a rule that can never fire because an earlier rule strictly subsumes it) | `0` ok, `2` invalid |
| `policy test <fixture.json>` | Evaluate a JSON-encoded Event against the policy, print verdict + matched rule. Used by the unit-test harness too | `0` |
| `verify [--session <id>]` | Recompute hash chain, verify `head_sig`, print `OK` or first bad `seq` | `0` valid, `3` tampered |
| `approve list\|allow <id>\|deny <id>` | Talk to a *running* supervisor socket; approve headless sessions from any terminal on the machine | `0` |
| `daemon` | Approval daemon detached from any child (for always-on agents like OpenClaw) | `0` |
| `__shim <bin> [args...]` | Hidden. Build Event → socket RPC → `syscall.Exec(realBin)` or exit 126 with deny message. Real binary resolved by scanning PATH *after* the shim dir | child's code; `126` denied; `77` check failed |

### 4.2 Supervisor / interception engine (`internal/supervisor/`, `internal/proxy/`, `internal/shim/`)

**Startup sequence (strict order; any failure aborts before the child spawns):**
1. `audit.Store.Open()` — migrate schema, insert `sessions` row, generate Ed25519 keypair.
2. `policy.NewEngine()` — compile all CEL; error → exit 2 with exact rule name + CEL error.
3. `egress.Listen("127.0.0.1:0")` → get actual port.
4. `mcp.StartProxies(cfg.MCPServers)` — spawn each real MCP server, hold its stdio pipes.
5. `shim.EnsureInstalled(cfg.Shims.Binaries)` — idempotent; shims are symlinks to `os.Executable()`; binaries not on PATH are skipped with a warning.
6. `socket.Serve(sockPath)` — `net.Listen("unix")`, chmod 0600.
7. Spawn child (`child.go`):
   ```go
   cmd := exec.Command(argv[0], argv[1:]...)
   cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
   cmd.Env = append(filteredEnv(),
       "PATH="+shimDir+":"+os.Getenv("PATH"),
       "HTTP_PROXY=http://"+egressAddr, "HTTPS_PROXY=http://"+egressAddr,
       "AGENTVAULT_SESSION="+sessionID, "AGENTVAULT_SOCK="+sockPath)
   ```
8. Forward `SIGINT/SIGTERM/SIGHUP` to the child process group. On child exit or supervisor signal: `logger.Flush()` (hard 5s deadline) → `chain.SignAndClose()` → remove socket → `os.Exit(childExitCode)`.

**Shim handler (`internal/shim/shim.go`)** — hot path, must add <15ms overhead:
1. Build `Event{Source: shim, Action: shell.exec, Cmd: filepath.Base(argv0), Argv, Raw, Cwd, PID}`.
2. Dial socket (200ms dial timeout) → send → read verdict (blocks up to approval timeout).
3. `allow` → `syscall.Exec(realBin, argv, env)` — replaces process, zero wrapper overhead after verdict.
4. `deny` → stderr: `agentvault: denied by rule "block-destructive-shell": <message>`; exit 126.
5. Socket error → exit 77 (fail closed).

**MCP proxy (`internal/proxy/mcp/`)**: newline-delimited JSON-RPC framing both directions. Pass through everything verbatim except `method == "tools/call"`: pause the message, map `params.name` + `params.arguments` → `Event{Source: mcp, Action: mcp.tool, Tool, ToolArgs}` (fs tools additionally set `Path`), evaluate, then forward to the real server or return JSON-RPC error `-32000, "blocked by AgentVault: <rule>"`. Responses proxied back unchanged. Per-tool overrides in `mcp_servers[].tool_policies` are checked *before* the global rule list.

**Egress proxy (`internal/proxy/egress/connect.go`)**: minimal CONNECT implementation — read `CONNECT host:port`, build `Event{Action: net.egress, Host, Port}`, evaluate, `200 Connection Established` + bidirectional `io.Copy` on allow, `403` on deny. No TLS interception, no payload logging (only host:port is audited — privacy by design).

### 4.3 Policy evaluator (`internal/policy/`)

```go
type Engine interface {
	Evaluate(e event.Event) event.Verdict // goroutine-safe, <1ms p99
}

// cel.go compiles at NewEngine time:
//   env, _ := cel.NewEnv(cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)))
// Per rule, evaluators run cheapest-first:
//   1. structural matchers (action ∈ list, glob match, host match)
//   2. CEL program last (short-circuits if structural already failed)
// Evaluate: for rule in rules { if match(rule, e) { return verdict(rule) } }
//           return verdict(defaults.action, ruleName="")
```

Matching helpers (`matcher.go`): `matchPath` via `github.com/bmatcuk/doublestar/v4` (`**` support, `~` pre-expanded); `matchHost` exact or `*.suffix`; shell CEL context exposes `event.cmd`, `event.argv`, `event.raw`, `event.cwd`. Ordering guarantee: **first match in document order wins** — documented loudly, as it's the #1 user error in firewall configs. `policy check` includes a shadowing linter (rule B unreachable if rule A's match ⊇ B's match).

Rate budget (`budgets.max_actions_per_minute`): token bucket in the supervisor; overflow converts any verdict to `require_approval`. Spend budget: v0.1 parses the field but logs "not yet enforced" (needs per-provider cost feed, §7) so the schema stays stable.

### 4.4 Approval daemon (`internal/approval/`)

```go
type Daemon struct {
	pending  map[string]*Request  // keyed by Event.ID, RWMutex-guarded
	memo     *MemoCache           // LRU, key=(rule, action, target), session-scoped
	channels []Channel            // telegram, tty
	timeout  time.Duration
}
type Channel interface {
	Ask(ctx context.Context, r Request) (<-chan Decision, error)
	Name() string
}
```

Flow: `Submit(event)` → memo hit? return memoized verdict → create `Request` → fan out `Ask` to all channels → `select` first decision vs `ctx.Done()` (timeout → deny) → memo-store if "allow rule" → broadcast "resolved" to other channels → return.

**Telegram (`telegram.go`):** long-poll `getUpdates`. Outgoing message:

```
🛡 AgentVault — approval requested
Agent: opencode · Rule: git-push-ask
Action: shell.exec
$ git push origin main
cwd: ~/projects/agentvault
[✅ Allow once] [🔁 Allow this rule] [❌ Deny]   (expires 0:47)
```

Inline keyboard callback_data: `av:<event_id>:once|:rule|:deny` (≤64 bytes; ULID fits). Only updates from configured `chat_id` are honored; all others are logged as suspicious. **TTY (`tty.go`):** renders the same card on stderr (stdout stays clean for the child), raw-mode single-key response, countdown via `\r` redraw — auto-disabled when stderr isn't a TTY.

### 4.5 Audit logger (`internal/audit/`)

```go
type Logger struct {
	store  *Store
	ch     chan record   // buffered 4096
	done   chan struct{}
	hasher *Chain        // single-goroutine owner of prev_hash
}
// Log() never blocks the agent's hot path: on a full channel it spills to
// ~/.agentvault/overflow.log and increments a dropped_events counter.
func (l *Logger) Log(e event.Event, v event.Verdict, d *event.Decision)
func (l *Logger) Flush(deadline time.Duration) error
```

`chain.go`: `Append(payload []byte) (rowHash [32]byte)` maintains `prev`; `SignAndClose()` writes `head_hash`+`head_sig` into `sessions` then zeroes the private key. `store.go` owns all SQL via `database/sql` + `modernc.org/sqlite` (driver `sqlite`), WAL mode, single writer goroutine. Retention: archive-then-delete — sessions with valid `head_sig` older than the cutoff are exported to `~/.agentvault/archive/<id>.jsonl` (sig included) before rows are removed, because deleting rows mid-chain would destroy verifiability.

### 4.6 TUI (`internal/tui/`)

BubbleTea model, three states: **table** (columns: time, action, target, verdict badge, rule; `/` filter, `v` cycle verdict filter, `enter` detail), **detail** (pretty-printed payload JSON, approval info, eval latency), **help**. Live-tail polls SQLite every 500ms for rows newer than cursor (works because supervisor and TUI share the DB — no extra IPC). Color-blind safe: verdict is a text badge `[ALLOW]/[DENY]/[ASK]`, never color alone.

---

## 5. 8-Week Execution Roadmap

Legend: **AC** = acceptance criteria. Every week ends with a tagged release (`v0.0.w`) and a short devlog post — shipping publicly every week is part of the growth engine, not an afterthought.

### Week 1 — Skeleton, config, policy engine
- Mon: repo init, go.mod, Cobra root, CI (lint+test+cross-compile), LICENSE/README stub.
- Tue–Wed: `internal/config` (parse, expand, validate) + `internal/event` + `policy.Engine` with structural matchers.
- Thu–Fri: CEL integration, `policy check` + `policy test` commands, 30 fixture tests in `policy/testdata/`.
- **AC:** `agentvault policy check` compiles the full example YAML in §3.1; `policy test` returns correct verdicts for 30 fixtures; CI green.

### Week 2 — Supervisor + shim channel (first end-to-end block)
- Mon–Tue: supervisor startup sequence, child env assembly, signal forwarding, socket server.
- Wed–Thu: `__shim` handler + `EnsureInstalled`; wire engine + naive synchronous file audit (SQLite lands next week).
- Fri: e2e harness + `run_block_test.go`.
- **AC:** `agentvault run -- fakeagent.sh` where fakeagent runs `rm -rf ~/fake-dir` → blocked with rule name in stderr, exit 126; allowed commands pass through with <15ms added latency (`hyperfine` benchmark in CI); demo GIF #1 (terminal block) recorded.

### Week 3 — Audit store, hash chain, verify
- Mon–Tue: `internal/audit` store + migrations + async logger with overflow.
- Wed: hash chain + Ed25519 sign-on-close; `agentvault verify`.
- Thu: tamper tests (flip a byte in the DB → `verify` reports exact bad `seq`; delete suffix → head mismatch).
- Fri: retention archive-then-delete.
- **AC:** 10k-event soak test with zero lost records (counter check); all tamper mutations detected; `go test -race ./...` clean.

### Week 4 — Approval daemon + Telegram (THE differentiator)
- Mon–Tue: daemon lifecycle, memo cache, timeout-deny path, TTY channel.
- Wed–Thu: Telegram channel with inline keyboards, chat_id pinning, "resolved elsewhere" updates, mock-server tests.
- Fri: `agentvault approve list/allow/deny` against a live supervisor socket.
- **AC:** `git push` inside a wrapped shell → Telegram message arrives <3s → tapping Deny blocks it and the audit row shows `approved_by=telegram:*` + wait time; timeout path denies at exactly 60s; demo GIF #2 (phone deny) recorded — **this is the launch asset.**

### Week 5 — MCP proxy channel
- Mon–Tue: JSON-RPC stdio framing both directions; fake MCP server fixture.
- Wed: `tools/call` interception, tool_policies precedence, JSON-RPC error synthesis.
- Thu–Fri: real-server integration test (`@modelcontextprotocol/server-filesystem`), per-tool `require_approval` → Telegram flow.
- **AC:** agent calling MCP `delete_file` on `~/.ssh` → denied with `-32000` error the agent gracefully handles; all non-tool messages pass through byte-identical (diffed in test).

### Week 6 — Egress proxy + TUI
- Mon–Tue: CONNECT proxy, host allowlist, `default: deny`, curl-through-proxy tests.
- Wed–Fri: `agentvault log` TUI (table/detail/filter/live-tail) + `--export json|csv`.
- **AC:** `curl https://evil.example` inside wrapped agent → 403 + audit row; TUI renders 100k-row log without lag (paged queries); live-tail shows events from a running session.

### Week 7 — Polish, init wizard, launch assets
- Mon: `init` wizard with agent auto-detection + Telegram bot guided setup.
- Tue: README (hook headline → GIF → 60-second quickstart → honest limitations), SECURITY.md threat model.
- Wed: `scripts/demo.sh` (deterministic asciinema recording) → final demo.gif.
- Thu: install.sh + goreleaser dry-run; `docs/integrations/opencode.md` + `openclaw.md`.
- Fri: `v0.1.0` tag; full clean-machine install test (fresh macOS VM + fresh Linux container).
- **AC:** a stranger can go `install.sh → init → run -- opencode → trigger a block` in under 5 minutes without reading anything but the README.

### Week 8 — Launch
- Mon: soft-launch in OpenClaw + OpenCode Discords and subreddits; gather bug reports.
- Tue: fix-forward pass.
- Wed 8–9am ET: Show HN ("AgentVault — a permission firewall for AI coding agents") + r/LocalLLaMA + X thread with the GIF; newsletter submission forms.
- Thu–Fri: respond to *everything* within hours; ship `v0.1.1` with launch-week fixes.
- **AC:** launch post is factually airtight (limitations stated, no overclaiming — security tools die on overclaiming); every issue answered <24h.

---

## 6. Testing Strategy

| Layer | What | How |
|---|---|---|
| Unit | matchers, CEL compile, config validate, chain math, memo cache | table-driven; fixtures in `testdata/` |
| Integration | shim↔socket, MCP roundtrip, egress allow/deny, telegram channel | fake MCP server, `httptest` Telegram API mock |
| E2E | full `run` against scripted fake agent | `test/e2e` + `fixtures/fakeagent.sh` |
| Tamper | DB mutation matrix | flip byte / delete row / delete suffix / reorder rows → `verify` must catch each |
| Performance | shim latency <15ms p99; eval <1ms p99 | `hyperfine` benchmark job in CI |
| Race/fuzz | `-race` on everything; fuzz JSON-RPC framing + YAML parse | `go test -race`, `go test -fuzz` |

**CI gates:** lint (golangci-lint), tests, race detector, benchmark regression check, cross-compile matrix (darwin/linux × amd64/arm64), and `goreleaser --snapshot`.

## 7. Risk Register & Non-Goals

| Risk | Mitigation |
|---|---|
| "Shims are bypassable — is this snake oil?" | Say so in README; v0.1 = guardrails + tamper-evident audit. Phase 2: macOS Seatbelt / Linux Landlock profiles generated from the same YAML → real confinement. That upgrade path is the v0.2 headline. |
| Telegram down / no network | TTY channel always available when attached; timeout defaults to deny; never blocks on network. |
| Latency complaints | Benchmarks in CI; shim exec-replacement keeps post-verdict overhead at zero. |
| YAML/CEL complexity scares users | `init` wizard writes a sane default; `policy check` gives exact line numbers; ship 5 copy-paste "recipe" policies in docs. |
| Approval fatigue | Memoized "allow this rule"; rate budget as a backstop instead of per-action prompts. |

**v0.1 non-goals (explicit):** TLS content inspection, kernel sandboxing, spend enforcement, multi-user/team policies, any cloud service. Each is a Phase 2+ item with the config schema already forward-compatible. **Windows IS supported in v0.1** (amended): shims are `.cmd` wrappers instead of symlinks, IPC is loopback TCP with a session token instead of a unix socket, and signal forwarding is Interrupt-only.
