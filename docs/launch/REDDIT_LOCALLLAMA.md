# r/LocalLLaMA post draft

**Title:**
I built a permission firewall for AI agents — they can't read your ~/.ssh or rm -rf your disk unless you say so (open source, single Go binary)

**Body:**

If you run coding agents (OpenCode, Claude Code, OpenClaw, whatever), they're running with your shell, your files, and your API keys. I wanted a bouncer, not a promise.

AgentVault sits between the agent and the world:

```bash
agentvault run -- opencode
```

- **YAML policy**: allow/deny/require_approval on shell commands, MCP tool calls, network egress, file paths. First match wins, default deny.
- **Phone approvals**: agent tries `git push` → Telegram message with [Allow once] [Allow rule] [Deny]. No answer in 60s → denied.
- **Tamper-evident audit log**: hash-chained SQLite + Ed25519 session signatures. `agentvault verify` proves nobody edited the record.
- **Kernel sandbox on macOS**: the same YAML generates a Seatbelt profile, so bypassing the userspace shims doesn't work — direct syscalls get EPERM.

The demo GIF is 20 seconds: agent attempts `rm -rf`, blocked, logged.

Stack: Go (single binary, no CGO), CEL for policy expressions, modernc.org/sqlite. Cross-platform: macOS/Linux/Windows (kernel layer is macOS-first, Landlock next). Apache-2.0.

Repo: <link>

Honest limitations in the README — I care more about being precise than being impressive. Feedback welcome, especially from people who break sandboxes for fun.
