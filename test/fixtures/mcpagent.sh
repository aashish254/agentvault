#!/usr/bin/env bash
# mcpagent: scripted agent that talks to its "filesystem" through the
# AgentVault MCP proxy. Portable to bash 3.2 (macOS): FIFOs, no coproc.
# AV_BIN is the agentvault binary path, AV_FIXTURES the fixtures dir.
set -u

echo "agent-start"

IN="$AV_WORK/mcp.in"
OUT="$AV_WORK/mcp.out"
rm -f "$IN" "$OUT"
mkfifo "$IN" "$OUT"

# The agent spawns its MCP server — wrapped by AgentVault.
"$AV_BIN" mcp proxy --server filesystem -- bash "$AV_FIXTURES/fakemcp.sh" < "$IN" > "$OUT" 2>/dev/null &
PROXY_PID=$!

# Hold both ends open for the whole conversation (no per-write EOF).
exec 3>"$IN"
exec 4<"$OUT"

send() { printf '%s\n' "$1" >&3; }

# 1. initialize — must pass through untouched.
send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fake","version":"0"}}}'

# 2. delete_file on ~/.ssh — must be DENIED by protect-credentials.
send '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"~/.ssh/id_rsa"}}}'

# 3. read_file inside the allowed workdir — must reach the real server.
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/work/ok.txt"}}}'

for i in 1 2 3; do
  if IFS= read -r -t 10 line <&4; then
    echo "resp$i=$line"
  else
    echo "resp$i=TIMEOUT"
  fi
done

exec 3>&-
exec 4<&-
kill "$PROXY_PID" 2>/dev/null
echo "agent-end"
