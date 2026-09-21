# OpenCode integration

OpenCode is wrapped with one command:

```bash
agentvault run -- opencode
```

Everything OpenCode does through its shell flows through the shim layer;
its HTTP traffic flows through the egress proxy (both configured by the
supervisor's child environment).

## MCP servers

If your `opencode.json` configures MCP servers, wrap them so their
`tools/call` traffic is policy-checked:

```jsonc
{
  "mcp": {
    "filesystem": {
      "type": "local",
      "command": [
        "agentvault", "mcp", "proxy", "--server", "filesystem", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "."
      ],
      "enabled": true
    }
  }
}
```

The proxy inherits `AGENTVAULT_SOCK` (unix) / `AGENTVAULT_ADDR`+`AGENTVAULT_TOKEN`
(Windows) from the supervised environment. Started outside a supervised
session, `tools/call` fails closed.

## Recommended starting rules

```yaml
rules:
  - name: protect-credentials
    match: {action: [fs.read, fs.write, fs.delete], path: ["~/.ssh/**", "~/.aws/**"]}
    effect: deny
  - name: git-push-ask
    match:
      action: [shell.exec]
      cel: 'event.cmd == "git" && event.argv.size() > 1 && event.argv[1] == "push"'
    effect: require_approval
```
