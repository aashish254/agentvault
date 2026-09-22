# 🛡 AgentVault

**A runtime permission firewall for AI agents.** Wrap any agent — Claude Code, OpenCode, OpenClaw, a shell script, anything — in declarative YAML rules, popup/phone approvals, and a tamper-evident audit log of everything it did.

```bash
agentvault run -- opencode
```

![demo](docs/img/demo.gif)

> ⚠️ **Scope, honestly.** On macOS the agent runs under a **kernel sandbox** (Seatbelt) generated from your policy — direct `/bin/rm` calls and raw sockets are blocked at the syscall layer. On Linux/Windows today: shims + proxies + tamper-evident audit (kernel backends are the v0.3 roadmap). Details: [SECURITY.md](SECURITY.md).

## Why

AI agents run with your shell, your files, your API keys. AgentVault answers: *what is the agent doing — and what is it allowed to do?*

- **Deny by default** — credentials, `rm -rf`, unknown egress blocked unless you say otherwise
- **One-tap approvals** — dangerous actions pop a native macOS dialog, page your phone (Telegram), or ask on the terminal — each showing *what* the agent wants and *what could go wrong*; approve once or approve the rule
- **Tamper-evident audit** — every action hash-chained in local SQLite, Ed25519-signed at session close; `agentvault verify` catches any tampering
- **Single static binary** — no daemons required, no cloud, no telemetry

## How it compares

Your agent's built-in sandbox (Claude Code, Codex) is good — if you only ever run that one agent, in that terminal, while you watch it. AgentVault is for everything past that:

| | AgentVault | Built-in agent sandboxes | Docker/VM |
|---|---|---|---|
| One policy across **every** agent you run | ✅ | ❌ each vendor's own | ✅ but no per-action rules |
| Tamper-evident, signed audit log | ✅ | ❌ | ❌ |
| Approvals on your phone (Telegram) | ✅ | ❌ | ❌ |
| Kernel-enforced (macOS Seatbelt) | ✅ | ✅ | ✅ |

Full, sourced, honest-about-our-gaps version: [docs/COMPARISON.md](docs/COMPARISON.md).

## Proof, not promises

```bash
make redteam   # 10 scripted attacks (shim bypass, base64 obfuscation, credential
               # theft, raw-socket egress, audit tampering) against the real binary
               # → docs/redteam/RESULTS.md
make bench     # policy-eval latency gate (<1ms p99)
```

The battery includes attacks we *don't* stop yet on platforms without a kernel backend — printed as KNOWN GAP, not hidden. Latest matrix: [docs/redteam/RESULTS.md](docs/redteam/RESULTS.md).

Measured against other sandboxes (real `make compare` run, default configs — reproduce with `go test -v -run TestCompareMatrix ./test/redteam/`):

![AgentVault vs srt vs Docker — measured attack outcomes](docs/redteam/COMPARE_CHART.png)

And at corpus scale — **103 real executed attack variants** (13 destructive, 52 credential-theft, 10 exfiltration, 16 evasion, 12 persistence), each verified to actually succeed unsandboxed, measured under every tool on the host — plus the axis most sandbox benchmarks hide: **8 everyday dev operations** (read, edit, build, commit, push, fetch) under the *same* tools and the *same* default configs (`make corpus` → [attack matrix](docs/redteam/CORPUS_RESULTS.md) · [legit-work matrix](docs/redteam/LEGIT_RESULTS.md)):

![103-attack corpus + legitimate-work battery: AgentVault 103/103 attacks blocked and 8/8 dev ops allowed — the only tool maxing both axes](docs/redteam/CORPUS_CHART.png)

Only AgentVault tops both axes: **103/103 attacks blocked *and* 8/8 legitimate operations allowed** — `git push` and network egress escalate to `require_approval` (terminal, macOS popup, or Telegram) instead of hitting a static deny. Anthropic's srt also blocked 103/103, but its zero-config default gets there by blocking *all* writes and *all* network: the agent can't edit a file, mkdir, commit, or fetch a package (3/8 legitimate ops). Codex CLI's default sandbox blocked 22/103 — full-disk reads and in-project destruction are outside its threat model. Docker blocked 4/92 — a container with a writable bind mount is not a sandbox.

The same data as one scorecard — every sandbox picks a side between *secure* and *usable*; AgentVault is alone in the top-right quadrant:

![Security vs usability scorecard: attacks blocked (%) vs legitimate work allowed (%) — AgentVault alone top-right at 100%/100%; srt top-left (100% blocked, 38% work); Codex and Docker bottom-right; no sandbox bottom-right corner](docs/redteam/SCORECARD_CHART.png)


## Install

```bash
curl -fsSL https://raw.githubusercontent.com/aashish254/agentvault/main/scripts/install.sh | sh   # checksum-verified, from GitHub Releases
agentvault init                                      # writes policy, installs shims
```

Or from source: `go build ./cmd/agentvault`.

## 60-second tour

```bash
agentvault policy check          # validate your rules
agentvault run -- bash           # wrap a shell
# inside:  rm -rf /tmp/x  → blocked (exit 126), you're told which rule
#          git push       → your phone pings: [Allow once] [Allow rule] [Deny]
agentvault log                   # live TUI: every action, verdict, rule, latency
agentvault verify                # prove nobody edited the log
```

Four channels are covered: **MCP tool calls** (stdio proxy), **shell commands** (PATH shims), **network egress** (CONNECT proxy), and **filesystem** (via the first two). Details: [docs/SPEC.md](docs/SPEC.md).

## Policy example

```yaml
version: 1
defaults: {action: deny}
rules:
  - name: protect-credentials
    match: {action: [fs.read, fs.write, fs.delete], path: ["~/.ssh/**", "~/.aws/**"]}
    effect: deny
  - name: git-push-ask
    match: {action: [shell.exec], cel: 'event.cmd == "git" && event.argv[1] == "push"'}
    effect: require_approval
```

More: [agentvault.example.yaml](agentvault.example.yaml) · [Policy recipes](docs/recipes/) · Integrations: [Claude Code](docs/integrations/claude.md) · [OpenCode](docs/integrations/opencode.md) · [OpenClaw](docs/integrations/openclaw.md)

## Status

Weeks 1–7 of the [8-week roadmap](docs/SPEC.md) complete. All platforms: macOS (arm64/amd64), Linux (arm64/amd64), Windows (arm64/amd64). Windows notes: `.cmd` shims, loopback-TCP IPC with session tokens, Interrupt-only signals.

## License

Apache-2.0
