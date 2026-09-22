# Policy recipes

Copy-paste starting points. Use one directly or merge pieces into your own
`agentvault.yaml`. Validate after editing: `agentvault policy check`.

| Recipe | What it does | Use it when |
|---|---|---|
| [protect-dotfiles.yaml](protect-dotfiles.yaml) | Agent works freely; credentials, keys, shell history, `.env` files are kernel-denied | Everyday driver |
| [repo-only.yaml](repo-only.yaml) | Agent can only touch the current project; `git push` asks first | Letting an agent loose on a codebase |
| [no-network-except-github.yaml](no-network-except-github.yaml) | Egress limited to GitHub + your LLM provider; everything else asks | Worried about exfiltration |
| [safe-autopilot.yaml](safe-autopilot.yaml) | Unattended runs; destructive/irreversible/unknown-network actions page your phone (Telegram) | Long-running agents while you're away |
| [read-only-reviewer.yaml](read-only-reviewer.yaml) | Read the project, answer questions; zero writes, zero network | Code review / explanation agents |

```bash
# try one:
agentvault run -c docs/recipes/repo-only.yaml -- opencode
```

On macOS, every recipe also generates a kernel Seatbelt profile from the same
rules — so the limits hold even if the agent bypasses the userspace shims.
On Linux/Windows today: userspace layers + tamper-evident audit (kernel
backends are the v0.3 roadmap; see [../../SECURITY.md](../../SECURITY.md)).
