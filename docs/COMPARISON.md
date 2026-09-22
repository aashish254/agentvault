# How AgentVault compares

*Last reviewed: September 2026. If something below is outdated, that's a bug — please open an issue or PR. We link sources for every claim and mark our own weaknesses honestly; security tools die on overclaiming.*

## The short version

**If you run exactly one agent, never leave it unattended, and don't need to prove what it did — use the sandbox built into your agent.** Claude Code's and Codex's built-in sandboxes are good, free, and zero-install. Seriously.

AgentVault exists for everything past that point:

1. **You run more than one agent.** One YAML policy, one approval inbox, one audit log across Claude Code, OpenCode, OpenClaw, shell scripts — whatever you wrap. Vendor sandboxes only protect their own agent, each with its own permission dialect.
2. **You need to *prove* what happened.** Every action is hash-chained into a local SQLite log, Ed25519-signed at session close. `agentvault verify` detects tampering. Vendor sandboxes enforce; they don't give you a tamper-evident flight recorder.
3. **The agent runs while you're away.** Approvals reach you on a native macOS dialog, Telegram, or the terminal — with what the agent wants and what could go wrong. Timeouts fail closed.

## The table

| Capability | AgentVault | Claude Code (permissions + [srt](https://github.com/anthropics/sandbox-runtime)) | [Codex CLI](https://github.com/openai/codex) sandbox | Docker / VM | firejail / bubblewrap |
|---|---|---|---|---|---|
| Works with **any** agent | ✅ | ❌ Claude Code only (srt itself wraps arbitrary commands, but has no policy/approval/audit layer) | ❌ Codex only | ✅ anything inside | ✅ |
| Kernel-enforced filesystem | ✅ macOS (Seatbelt); Linux/Windows on roadmap | ✅ Seatbelt / bubblewrap | ✅ Seatbelt / Landlock / Win DACL | ✅ container boundary | ✅ Linux only |
| Per-command shell policy (CEL) | ✅ | ⚠️ allow/deny rules, no expressions | ⚠️ coarse modes | ❌ | ❌ |
| MCP tool-call interception | ✅ stdio proxy | ⚠️ its own tools only | ⚠️ its own tools only | ❌ | ❌ |
| Network egress policy | ✅ per-host, default-deny | ✅ | ✅ (network off in full isolation) | ⚠️ manual | ⚠️ manual netns |
| Human-in-the-loop approvals | ✅ terminal / native popup / **Telegram** | ✅ in-terminal | ✅ in-terminal | ❌ | ❌ |
| Approve from your phone | ✅ | ❌ | ❌ | ❌ | ❌ |
| Tamper-evident audit log | ✅ hash chain + Ed25519 seal | ❌ transcripts, not tamper-evident | ❌ | ❌ | ❌ |
| Single static binary, no daemon | ✅ | ✅ | ✅ | ❌ | ⚠️ setuid helper |
| Runs on macOS + Linux + Windows | ✅ (enforcement depth varies — see SECURITY.md) | ⚠️ macOS/Linux | ✅ | ✅ | ❌ Linux only |

## Where AgentVault is honestly behind

- **Linux/Windows kernel enforcement.** Today those platforms get shims + proxies + tamper-evident audit, not confinement. Landlock/JobObjects are the v0.3 roadmap. Our red-team battery reports these as KNOWN GAP rows rather than hiding them.
- **Maturity.** The vendor sandboxes ship with the agent and are battle-tested by their user base. AgentVault is young; our answer is a public test suite (135+ tests) and a red-team battery anyone can run, not "trust us."
- **TLS payload inspection.** Out of scope by design — egress decisions are host:port only.

## Don't take our word for it

```bash
make redteam   # runs 10 scripted attacks against the real binary,
               # writes docs/redteam/RESULTS.md
make compare   # runs the same attacks under srt/Docker/firejail too,
               # writes docs/redteam/COMPARE_RESULTS.md
make bench     # policy-eval latency gate (<1ms p99; ~1–5µs typical)
make race      # full suite under the race detector
```

The red-team battery includes attacks AgentVault is *expected* to stop (shim bypass via direct `/bin/rm`, base64-obfuscated commands, credential reads, raw-socket egress, audit-log tampering) and attacks it honestly doesn't stop yet on platforms without a kernel backend. Both are printed in the results matrix.

`make compare` goes further: it executes the same attacks under every sandbox tool installed on your machine (Anthropic's `srt`, Docker, firejail) and records the *measured* outcome per tool — no assertions about competitors, just data. Install the tools and run it yourself; the matrix regenerates with whatever it finds.

![Measured cross-tool results chart](redteam/COMPARE_CHART.png)

![Measured cross-tool results table](redteam/COMPARE_RESULTS.png)

Latest run (2026-09-22, darwin/arm64, real `srt` 1.0.0 and Docker Desktop installed): AgentVault blocked all three attacks; `srt` and Docker let the destructive delete and credential read through under default configuration (srt blocked the egress). Defaults aren't the whole story — every tool above can be *configured* to block some of these — but defaults are what most users run. [Full results](redteam/COMPARE_RESULTS.md) · [Live opencode-under-AgentVault transcript](redteam/LIVE_DEMO.md)
