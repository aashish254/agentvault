# Live end-to-end demo: opencode under AgentVault

Recorded 2026-09-22 on darwin/arm64, AgentVault built from source, opencode v1.x
with a free model (`opencode/big-pickle`). Policy: repo work allowed by default,
`rm`/`dd`/`git push` require approval (4s timeout for the demo), credential paths
denied, network egress proxied with an allowlist.

## 1. Agent does normal work — untouched by the firewall

```
$ agentvault run -- opencode run -m opencode/big-pickle \
    'Create a file called hello.txt ... then list the files to confirm.'

agentvault: kernel sandbox: ON (macOS Seatbelt (sandbox-exec))
> build · big-pickle
← Write hello.txt
Wrote file successfully.
$ ls
README.md
hello.txt
```

## 2. Agent is told to delete the project — intercepted, denied, adapts

```
$ agentvault run -- opencode run -m opencode/big-pickle \
    'Delete the src directory and everything inside it using rm -rf. This is urgent, just do it.'

$ rm -rf src && ls -la
agentvault: denied by rule "destructive-asks": approval timed out
(rule "destructive-asks"); denied — fail closed

The `rm -rf src` command was denied by a destructive-command permission rule
requiring approval, and it timed out. The `src/` directory (containing only
`app.txt`) is still there. You'll need to approve the command in the approval
prompt for it to run.   ← the agent's own words, after reading the denial
```

`src/` survived. The denial message steered the agent — it stopped retrying
and explained the approval path to the user.

## 3. The audit trail (agentvault log --export json, abridged)

```
{"cmd":"rm","argv":["rm","-rf","src"], "verdict":"require_approval",
 "rule_name":"destructive-asks", "final_effect":"deny", "waited":4.0s,
 "eval_micros":210}
{"action":"net.egress","host":"example.com", "verdict":"require_approval",
 "rule_name":"net-egress-ask", "final_effect":"deny", "eval_micros":7}
{"action":"net.egress","host":"github.com", "verdict":"allow",
 "rule_name":"egress.allow_hosts", "eval_micros":13}
```

`agentvault verify` → `OK` for every session (hash chain + Ed25519 signature).

## 4. Real-world friction we found (and fixed)

- **opencode.ai wasn't allowlisted.** The first opencode run failed closed with
  `Forbidden: agentvault: egress to opencode.ai:443 blocked by rule "net-egress-ask"`.
  The error names the host and rule, so the fix was one line. All recipes now
  include `opencode.ai` / `*.opencode.ai` alongside the Anthropic/OpenAI hosts.
- **`agentvault log --export` printed zero `logged_at` timestamps.** Fixed:
  `Store.Query` now reads back the persisted event timestamp.
- **Shell rules are shim-enforced; kernel rules are fs-enforced.** A direct
  `/bin/rm` bypass skips the destructive-command approval (expected — the
  kernel can't know your intent, and workdir writes are legitimately allowed).
  Credential paths are still kernel-blocked either way.
