# Claude Code integration

Claude Code has a [hooks system](https://docs.claude.com/en/docs/claude-code/hooks):
before any tool runs (Bash, Read, Write, Edit, WebFetch, MCP tools — everything),
Claude pipes the call to `agentvault hook claude`, which asks the running
AgentVault supervisor for a verdict. Exit 0 allows the tool; exit 2 blocks it
and hands the policy message back to Claude as feedback (so the agent can adapt
instead of retrying blindly).

## Setup

```sh
agentvault integrate claude          # writes .claude/settings.json (project-level)
agentvault run -- claude             # or any agent command
```

`integrate` appends one entry to `hooks.PreToolUse` in the project's
`.claude/settings.json` (existing hooks are preserved, re-running is
idempotent, and the previous file is backed up to
`settings.json.agentvault-backup`).

## What gets checked

| Claude tool                    | AgentVault event                  |
| ------------------------------ | --------------------------------- |
| `Bash`                         | `shell.exec` (cmd + full argv)    |
| `Write` / `Edit` / `MultiEdit` | `fs.write` (path)                 |
| `Read` / `Glob` / `Grep` / `LS`| `fs.read` (path)                  |
| `WebFetch`                     | `net.egress` (host)               |
| everything else (incl. MCP)    | `mcp.tool` (lowercased tool name) |

Tool names are lowercased, so one policy covers opencode and Claude alike
(`TodoWrite` → `todowrite`, matched by the default `allow-benign-agent-tools`).

## Behavior

- Inside `agentvault run`: every tool call is policy-checked;
  `require_approval` rules freeze the tool call until you answer on the
  popup dialog / TTY / Telegram / `agentvault approve`; everything lands in
  the tamper-evident audit log. Shims, the egress proxy, and the macOS
  Seatbelt sandbox still apply underneath.
- Outside a session (no `AGENTVAULT_SOCK`): the hook exits 0 — vanilla
  Claude Code, no interference.
- Unreachable supervisor: the hook exits 2 (fail closed).

## Claude Code's own permissions vs. this

Claude Code's built-in allow/deny prompts only gate what goes through its
own tool layer, approvals are per-tool-pattern and easy to "always allow"
away, and there is no tamper-evident record. AgentVault adds a second,
agent-agnostic boundary: the same YAML policy across every agent you run,
a signed hash-chained audit log you can verify after the fact, network
egress control, and (on macOS) kernel-level sandboxing of the whole
process tree.
