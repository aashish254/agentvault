# OpenClaw integration

OpenClaw is a long-running personal agent (not a per-task CLI), so the
recommended shape is the always-on daemon plus a supervised start:

```bash
# Terminal 1 — approvals stay answerable even when you detach:
agentvault daemon            # serves approvals over the session IPC

# Terminal 2 — the agent itself, supervised:
agentvault run -- openclaw gateway
```

Every shimmed command and egress connection OpenClaw makes is evaluated
against `agentvault.yaml` and recorded in the hash-chained audit log.
With Telegram enabled you get one-tap approve/deny on your phone —
the point of the exercise when the agent acts while you're away.

## Suggested policy for always-on agents

Be stricter than for interactive coding agents — the agent runs unattended:

```yaml
defaults:
  action: deny            # anything unlisted is blocked
rules:
  - name: read-only-workspace
    match: {action: [fs.read], path: ["~/openclaw/**"]}
    effect: allow
  - name: workspace-writes-ask
    match: {action: [fs.write, fs.delete], path: ["~/openclaw/**"]}
    effect: require_approval
  - name: no-credential-reads
    match: {action: [fs.read, fs.write, fs.delete], path: ["~/.ssh/**", "~/.aws/**", "**/*.pem"]}
    effect: deny
  - name: known-apis-only
    match: {action: [net.egress], not_host: ["api.anthropic.com", "api.openai.com"]}
    effect: require_approval
```

## Messaging channels

If OpenClaw manages WhatsApp/Telegram itself, those flows are *outbound
network* from AgentVault's view: control them with `net.egress` rules,
and audit them with `agentvault log --export json --action net.egress`.
