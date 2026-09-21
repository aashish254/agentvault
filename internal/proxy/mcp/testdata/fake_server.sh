#!/bin/sh
# fake MCP server: newline-delimited JSON-RPC. Echoes a fixed result for
# every request, embedding the request id so callers can correlate.
while IFS= read -r line; do
  # extract "id":N (crude but sufficient for a fixture)
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  [ -z "$id" ] && id=0
  printf '{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}\n' "$id"
done
