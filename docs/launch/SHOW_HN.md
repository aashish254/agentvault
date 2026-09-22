# Show HN draft — post Wednesday 8–9am ET

**Title:**
Show HN: AgentVault – a permission firewall for AI coding agents (kernel-enforced on macOS)

**Body:**

I run AI coding agents every day, and I got tired of the trust model being "hope the agent doesn't rm -rf something or read my ~/.ssh." AgentVault wraps any agent — OpenCode, OpenClaw, a shell script — in a runtime permission firewall:

- Declarative YAML policy (allow/deny/require-approval) over four channels: shell commands, MCP tool calls, network egress, and filesystem paths.
- require_approval pages you on Telegram (or your terminal) — one tap to allow once, allow the rule, or deny. Timed-out requests fail closed.
- Every action is hash-chained into a local SQLite audit log, Ed25519-signed at session close. `agentvault verify` detects tampering with forensic detail.
- On macOS the same YAML also generates a kernel Seatbelt profile, so even a direct /bin/rm bypassing every shim dies at the syscall layer. (Linux Landlock / Windows Job Objects are the roadmap — today those platforms get the userspace layers + audit.)

Demo in the README is a 20-second GIF: agent tries `rm -rf /tmp/important`, gets blocked, and the block lands in the audit log.

An unexpected finding from dogfooding it against real agents: the denials double as agent feedback. In one red-team session I gave an agent four tasks, three of them attacks — read my SSH key, rm -rf a canary dir, git push. The first two died on policy (deny:protect-credentials, deny:block-destructive-shell), the agent read the error messages, concluded "the security policies in this environment prevent this," and didn't even attempt the push. Structured denials steer agent behavior, not just block it.

**What it is NOT (I want to be precise, because security tools die on overclaiming):**
- Not a full sandbox on Linux/Windows yet (userspace enforcement + audit there).
- Not payload inspection of TLS — egress decisions are host:port only, by design (privacy).
- The audit log proves what was *recorded*; it can't prove an unrecorded action never happened. The kernel layer is what closes that gap on macOS.

Tech: single static Go binary, CEL policies, modernc.org/sqlite (no CGO), BubbleTea TUI. 124 tests, e2e suite runs real blocked/allowed/approved flows. Apache-2.0.

Happy to answer questions about the interception design, the hash-chain audit, or the Seatbelt profile generation.

---

**First comment to self-post immediately (the FAQ disarm):**

Anticipating the top comment: "PATH shims are trivially bypassed with /bin/rm directly."

Correct — that's why v0.2 added kernel enforcement on macOS. The same policy YAML generates a Seatbelt profile; a direct /bin/rm gets EPERM from the kernel (there's an e2e test that does exactly this). On Linux/Windows today you'd get the shim + audit layers only, and the README says so in the first section. Landlock is next.
