# Contributing to AgentVault

Thanks for your interest! The project is in its initial 8-week sprint —
see `docs/SPEC.md` for the full specification and roadmap.

## Ground rules

1. **Fail closed.** Any ambiguity, error, or unreachable dependency must
   result in DENY, never silent allow. PRs that weaken this are rejected.
2. **No overclaiming.** Docs and code comments must be precise about what
   is enforced vs. best-effort. Security tools die on overclaiming.
3. **Tests are part of the change.** Every policy/audit/approval change
   ships with tests; `go test -race ./...` must pass.

## Development

```bash
make build   # build bin/agentvault
make race    # full race-enabled test suite
make bench   # policy engine benchmark (target: <1ms p99)
```

Layout and module contracts: `docs/SPEC.md` §2 and §4.

## Commit style

Conventional-ish: `policy: add host suffix matching`, `audit: fix chain
verify on empty session`. Small, focused commits beat big ones.
