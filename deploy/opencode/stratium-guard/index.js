// Stratium guard for OpenCode 2.x.
//
// OpenCode has no command hooks, so this plugin is the hook: before every tool
// call it runs `stratium-pep hook --harness opencode` with the call on stdin
// and rejects the call unless that exits 0. `deploy/stratium --opencode
// install` copies this directory and writes stratium.json beside this file.
//
// One rule shapes the file: OpenCode skips a plugin that throws while it
// loads, and every tool then runs unchecked. So nothing here can throw before
// the hook is registered, and everything that can go wrong afterwards (no
// settings file, no binary, a timeout) happens inside a call, where it
// refuses that call.
import { spawn } from "node:child_process"
import { readFileSync } from "node:fs"

const SIDE_TIMEOUT_MS = 15_000 // session-start and report

// { "bin": "/path/to/stratium-pep", "config": "/etc/stratium/pep.env" | null,
//   "timeoutMs": 150000 }. Read per call, so a bad file refuses calls and a
// fixed one is picked up without a restart.
function settings() {
  const s = JSON.parse(readFileSync(new URL("./stratium.json", import.meta.url), "utf8"))
  if (typeof s.bin !== "string" || !s.bin) throw new Error("stratium.json has no bin")
  return s
}

// Runs stratium-pep and resolves { code, stderr }. Never rejects: code is 0
// only when the process ran and exited 0.
export function pep(args, payload, timeoutMs) {
  return new Promise((resolve) => {
    let timer
    const done = (result) => (clearTimeout(timer), resolve(result))
    const fail = (why) => done({ code: -1, stderr: `stratium guard: ${why}` })
    try {
      const s = settings()
      const child = spawn(s.bin, [...args, ...(s.config ? ["--config", s.config] : [])], {
        stdio: ["pipe", "ignore", "pipe"],
      })
      // Our own timer, not spawn's `timeout`: that one is left running when
      // the binary cannot be started.
      const limit = timeoutMs ?? s.timeoutMs ?? 150_000
      timer = setTimeout(() => (child.kill("SIGKILL"), fail(`${s.bin} did not answer in ${limit} ms`)), limit)
      let stderr = ""
      child.stderr.on("data", (chunk) => (stderr += chunk))
      child.on("error", (err) => fail(`could not run ${s.bin}: ${err.message}`))
      child.on("close", (code, signal) =>
        code === null ? fail(`${s.bin} was stopped (${signal}) before it answered`) : done({ code, stderr }),
      )
      child.stdin.on("error", () => {})
      child.stdin.end(payload === undefined ? "" : JSON.stringify(payload))
    } catch (err) {
      fail(err.message)
    }
  })
}

// tool_name and tool_input are passed through untouched: the PDP knows
// OpenCode's tool names (it is told `--harness opencode`) and reads the paths
// itself. cwd is what it resolves relative paths against.
const call = (ctx, event) => ({ tool_name: event.tool, tool_input: event.input, cwd: ctx.location?.directory })

export default {
  id: "stratium.guard",
  async setup(ctx) {
    await ctx.tool.hook("execute.before", async (event) => {
      const { code, stderr } = await pep(["hook", "--harness", "opencode"], call(ctx, event))
      if (code !== 0) throw new Error(stderr.trim() || `stratium-pep refused the call (exit ${code})`)
    })
    // From here on a failure must not undo the hook above, so nothing throws.
    try {
      // Tells the PDP a call ran, so it can flag one it never allowed. Fires
      // for calls that failed too, and not for calls the hook above refused.
      await ctx.tool.hook("execute.after", async (event) => {
        await pep(["report"], call(ctx, event), SIDE_TIMEOUT_MS)
      })
    } catch (err) {
      console.error(`stratium guard: tool calls will not be reported: ${err.message}`)
    }
    // OpenCode has no session-start hook. This runs once per place the plugin
    // is loaded for; if it fails, every call is refused for want of a session.
    const started = await pep(["session-start"], undefined, SIDE_TIMEOUT_MS)
    if (started.code !== 0) console.error(started.stderr.trim() || "stratium guard: session-start failed")
  },
}
