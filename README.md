# 🛡 AgentVault

**A runtime permission firewall for AI agents.** Wrap any coding agent — OpenCode, OpenClaw, anything — in declarative YAML rules, one-tap phone approvals, and a tamper-evident audit log of everything it did.

```bash
agentvault run -- opencode
```

> ⚠️ **Early development.** v0.1 is guardrails + tamper-evident audit, not a kernel sandbox. Determined agents can bypass PATH shims; kernel-level confinement (macOS Seatbelt / Linux Landlock) generated from the same YAML is the v0.2 roadmap. See [SECURITY.md](SECURITY.md).

## Why

AI agents now run with access to your shell, files, and API keys. AgentVault answers one question: *what is the agent actually doing — and what is it allowed to do?*

- **Deny by default** — credentials, destructive commands, and unknown network egress are blocked unless you say otherwise
- **One-tap approvals** — dangerous actions page your phone (Telegram) or terminal; approve once, or approve the rule
- **Tamper-evident audit** — every action hash-chained into a local SQLite log, Ed25519-signed at session close; `agentvault verify` detects any tampering
- **Zero dependencies** — one static Go binary

## Status

Week 1 of the [8-week roadmap](docs/SPEC.md): policy engine (CEL + glob matchers), `policy check` / `policy test`, full test suite. Interception channels land Weeks 2–6.

```bash
cp agentvault.example.yaml agentvault.yaml
agentvault policy check
agentvault policy test internal/policy/testdata/fixture_rm_rf.json
# → verdict=deny rule=block-destructive-shell
```

## License

Apache-2.0
