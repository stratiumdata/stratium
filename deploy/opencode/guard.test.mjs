// node deploy/opencode/guard.test.mjs
// Drives the plugin with a stand-in for OpenCode's plugin context and a shell
// script for stratium-pep. It checks this file's logic, not OpenCode's loader.
import assert from "node:assert/strict"
import { chmodSync, cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { pathToFileURL } from "node:url"

const dir = mkdtempSync(join(tmpdir(), "stratium-guard-"))
try {
  const guard = join(dir, "stratium-guard")
  cpSync(new URL("./stratium-guard", import.meta.url), guard, { recursive: true })
  const log = join(dir, "calls.log")
  const bin = join(dir, "stratium-pep")
  // Logs "<args> <stdin>", refuses any call whose input mentions "secret".
  writeFileSync(bin, `#!/bin/sh
in=$(cat)
echo "$* $in" >> "${log}"
case "$1" in hook) case "$in" in *secret*) echo "denied by policy" >&2; exit 2;; *slow*) sleep 5;; esac;; esac
exit 0
`)
  chmodSync(bin, 0o755)
  const configure = (s) => writeFileSync(join(guard, "stratium.json"), JSON.stringify(s))
  configure({ bin, config: "/etc/stratium/pep.env", timeoutMs: 1000 })

  const plugin = (await import(pathToFileURL(join(guard, "index.js")).href)).default
  assert.equal(plugin.id, "stratium.guard")
  const hooks = {}
  const ctx = { location: { directory: "/work" }, tool: { hook: async (name, cb) => void (hooks[name] = cb) } }
  await plugin.setup(ctx)
  const lines = () => readFileSync(log, "utf8").trim().split("\n")
  assert.equal(lines()[0], "session-start --config /etc/stratium/pep.env")

  // allowed: resolves, and the call went out untouched with the cwd
  const event = { tool: "read", input: { path: "README.md" }, sessionID: "s", agent: "a", messageID: "m", id: "c" }
  await hooks["execute.before"](event)
  assert.equal(lines().at(-1),
    'hook --harness opencode --config /etc/stratium/pep.env {"tool_name":"read","tool_input":{"path":"README.md"},"cwd":"/work"}')
  assert.deepEqual(event.input, { path: "README.md" })

  // refused: rejects with the binary's stderr as the reason
  await assert.rejects(hooks["execute.before"]({ tool: "read", input: { path: "secret.txt" } }), /denied by policy/)
  // too slow: the call is refused, not let through
  await assert.rejects(hooks["execute.before"]({ tool: "shell", input: { command: "slow" } }), /did not answer in 1000 ms/)

  // after: reported with the same bytes, for a failure as for a success
  await hooks["execute.after"]({ ...event, status: "error", error: new Error("x") })
  assert.equal(lines().at(-1),
    'report --config /etc/stratium/pep.env {"tool_name":"read","tool_input":{"path":"README.md"},"cwd":"/work"}')

  // no --config when none is set
  configure({ bin, config: null, timeoutMs: 1000 })
  await hooks["execute.before"](event)
  assert.ok(lines().at(-1).startsWith("hook --harness opencode {"))

  // every broken setup refuses the call, and none of them stops setup
  for (const broken of [{ bin: join(dir, "missing") }, { bin: "" }, null]) {
    if (broken) configure(broken)
    else rmSync(join(guard, "stratium.json"))
    await assert.rejects(hooks["execute.before"](event), /stratium guard: /)
    await hooks["execute.after"]({ ...event, status: "completed" })
    const again = {}
    await plugin.setup({ ...ctx, tool: { hook: async (name, cb) => void (again[name] = cb) } })
    assert.ok(again["execute.before"])
  }

  // a host with no after hook keeps the before hook
  configure({ bin, config: null, timeoutMs: 1000 })
  const only = {}
  await plugin.setup({ location: {}, tool: { hook: async (name, cb) => {
    if (name !== "execute.before") throw new Error("no such hook")
    only[name] = cb
  } } })
  await only["execute.before"](event)
  console.log("guard test OK")
} finally {
  rmSync(dir, { recursive: true, force: true })
}
