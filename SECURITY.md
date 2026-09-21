# Security Model & Disclosure

## Threat model (v0.1)

AgentVault v0.1 provides **guardrails and tamper-evident audit**, not a
kernel sandbox. Specifically:

| Covered | Not covered in v0.1 |
|---|---|
| Shell commands via PATH shims (`rm`, `git`, `curl`, …) | Agent calling a binary by absolute path, bypassing the shim |
| MCP tool calls via stdio proxy | Agents configured to ignore the wrapped MCP server |
| Network egress via HTTP(S)_PROXY env | Processes that ignore proxy env vars or use raw sockets |
| Audit-tamper detection (hash chain + Ed25519) | An agent with enough access deleting the whole DB file |

The child agent runs as your user, with your ambient authority. A
sufficiently capable or adversarial agent **can** bypass v0.1 enforcement.
Kernel-level confinement (macOS Seatbelt / Linux Landlock profiles
generated from the same policy YAML) is the v0.2 roadmap.

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
