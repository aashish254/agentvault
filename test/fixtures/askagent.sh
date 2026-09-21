#!/usr/bin/env bash
# askagent: scripted agent whose git push requires approval.
# test/e2e approves it via `agentvault approve allow` from a second
# process — the full Week-4 flow.
set -u

echo "agent-start"
git push origin main 2>&1 | tail -1
echo "push-exit=${PIPESTATUS[0]}"
echo "agent-end"
