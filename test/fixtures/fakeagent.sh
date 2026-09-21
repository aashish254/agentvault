#!/usr/bin/env bash
# fakeagent: scripted "AI agent" that attempts both benign and
# destructive actions. Used by test/e2e to verify end-to-end blocking.
set -u

echo "agent-start"

# Benign: ls must pass through (rule allows it).
ls /tmp > /dev/null && echo "ls-ran"

# Malicious: rm must be blocked by the shim with exit 126.
rm -rf "${AV_WORK:?}/victim" 2>&1
echo "rm-exit=$?"

# Irreversible: git push requires approval; with no approval daemon
# running it must fail closed (exit 126, explanation on stderr).
git push origin main 2>&1
echo "push-exit=$?"

echo "agent-end"
