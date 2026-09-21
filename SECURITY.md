# Security Model & Disclosure

## Threat model (v0.2)

With `sandbox.enabled: true` on macOS, the child process runs under a
**kernel-enforced Seatbelt profile** generated from the same
`agentvault.yaml`:

| Covered | Not covered yet |
|---|---|
| Shell commands via PATH shims (policy-evaluated) | |
| **Direct binary calls bypassing shims** — kernel denies the fs write/read | Linux (Landlock) & Windows (Job Objects) — v0.3 roadmap |
| MCP tool calls via stdio proxy | |
| Network egress via proxy env; with egress on, `deny network-outbound` forces all TCP through the proxy | Payload inspection of proxied TLS (host:port only, by design) |
| Audit-tamper detection (hash chain + Ed25519) | An agent deleting the DB file itself is blocked by sandbox write-deny outside the vault — but a non-sandboxed supervisor could still be killed |
| Credential paths (`~/.ssh`, `~/.aws`, …) at BOTH layers | Memory/IPC-based exfiltration (out of scope) |

**macOS note:** `sandbox-exec` is deprecated-but-functional since Catalina.
We degrade loudly (`kernel sandbox: OFF — <reason>`), never silently.

## What the audit log guarantees

- Every recorded event is hash-chained: editing or deleting any row breaks
  the chain and is reported by `agentvault verify`.
- The chain head is Ed25519-signed at session close with an ephemeral key
  that is destroyed on exit. Forging a valid tail after the fact requires
  the live session key.
- The log proves *what was recorded*. It cannot prove an unrecorded action
  never happened (see bypasses above).

## Reporting a vulnerability

Please **do not** open a public issue for security reports.
Email: security@agentvault.dev (placeholder until the project email exists —
open a private GitHub Security Advisory in the meantime).

We aim to acknowledge within 48 hours.


## What the audit log guarantees

- Every recorded event is hash-chained: editing or deleting any row breaks
  the chain and is reported by `agentvault verify`.
- The chain head is Ed25519-signed at session close with an ephemeral key
  that is destroyed on exit. Forging a valid tail after the fact requires
  the live session key.
- The log proves *what was recorded*. It cannot prove an unrecorded action
  never happened (see bypasses above).

## Reporting a vulnerability

Please **do not** open a public issue for security reports.
Email: security@agentvault.dev (placeholder until the project email exists —
open a private GitHub Security Advisory in the meantime).

We aim to acknowledge within 48 hours.
