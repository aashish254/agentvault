// AgentVault plugin for OpenCode.
// Reports EVERY tool call to the agentvault supervisor (unix socket) and
// throws on deny — OpenCode then shows the agent a normal tool error.
// Installed by: agentvault integrate opencode
//
// Design notes:
// - No SOCK (running outside agentvault) -> allow. Standalone use.
// - Socket error inside agentvault -> DENY. Fail closed (SPEC 1.1).

const SOCK = process.env.AGENTVAULT_SOCK
const TOKEN = process.env.AGENTVAULT_TOKEN ?? ""
const SESSION = process.env.AGENTVAULT_SESSION ?? ""

let uidCounter = 0
function uid() {
  const t = Date.now().toString(36).padStart(10, "0")
  return "av" + t + (++uidCounter).toString(36).padStart(6, "0") + Math.random().toString(36).slice(2, 6)
}

function buildEvent(tool: string, args: any): any {
  const ev: any = {
    id: uid(),
    session_id: SESSION,
    ts: new Date().toISOString(),
    source: "opencode-plugin",
    action: "mcp.tool",
    tool: tool,
    cwd: process.cwd(),
    pid: process.pid,
  }
  switch (tool) {
    case "bash":
      ev.action = "shell.exec"
      ev.cmd = String(args.command ?? "").split(/\s+/)[0] ?? ""
      ev.argv = [ev.cmd]
      ev.raw = String(args.command ?? "")
      break
    case "write":
    case "edit":
    case "patch":
      ev.action = "fs.write"
      ev.path = String(args.filePath ?? args.path ?? "")
      break
    case "read":
      ev.action = "fs.read"
      ev.path = String(args.filePath ?? args.path ?? "")
      break
    case "glob":
    case "grep":
    case "list":
      // Read-only file tools: govern by path so protect-credentials still
      // catches ~/.ssh snooping and workdir-is-free allows local use.
      ev.action = "fs.read"
      ev.path = args.path ? String(args.path) : process.cwd()
      break
    case "webfetch":
      ev.action = "net.egress"
      ev.host = String(args.url ?? "").replace(/^https?:\/\//, "").split(/[/:]/)[0]
      ev.port = 443
      break
  }
  return ev
}

function ask(ev: any): Promise<string> {
  return new Promise((resolve) => {
    if (!SOCK) {
      resolve("allow:no-session")
      return
    }
    let buf = ""
    let done = false
    const finish = () => {
      if (done) return
      done = true
      try {
        const resp = JSON.parse(buf)
        if (resp.type !== "verdict") {
          resolve("deny:bad-response")
          return
        }
        resolve(resp.effect + (resp.rule_name ? ":" + resp.rule_name : ""))
      } catch {
        resolve("deny:bad-json")
      }
    }
    const c = Bun.connect({
      unix: SOCK,
      socket: {
        data(_s: any, data: any) { buf += data.toString(); finish() },
        end() { finish() },
        error(_s: any, err: any) { resolve("deny:socket-error:" + String(err)) },
      },
    })
    c.then((sock) => {
      if (sock) sock.write(JSON.stringify({ type: "eval", token: TOKEN, event: ev }) + "\n")
    }).catch((e) => {
      resolve("deny:connect-error:" + String(e))
    })
    setTimeout(() => finish(), 30000) // approval timeout backstop
  })
}

export const AgentVaultPlugin = async (ctx: any) => {
  return {
    "tool.execute.before": async (input: any, output: any) => {
      const ev = buildEvent(input.tool, output.args ?? {})
      const result = await ask(ev)
      if (result.startsWith("allow")) {
        return // proceed
      }
      throw new Error(`AgentVault: blocked by policy (${result})`)
    },
  }
}
