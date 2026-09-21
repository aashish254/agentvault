#!/usr/bin/env bash
# fakemcp: minimal MCP stdio server for e2e. Newline-delimited JSON-RPC;
# answers every request with a fixed result carrying the request id.
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  [ -z "$id" ] && continue
  printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true,"content":[{"type":"text","text":"done"}]}}\n' "$id"
done
