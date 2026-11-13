// code-watch managed plugin
const ARGV = __ARGV__
const FAIL_OPEN = __FAIL_OPEN__
const TIMEOUT_MS = 10000
const UNCHECKED = __UNCHECKED__

export const CodeWatch = async ({ directory }) => ({
  "tool.execute.before": async (input, output) => {
    if (input.tool !== "bash") return
    let reason
    try {
      const proc = Bun.spawn(ARGV, { stdin: "pipe", stdout: "pipe", stderr: "inherit" })
      const timer = setTimeout(() => proc.kill(), TIMEOUT_MS)
      let text, code
      try {
        proc.stdin.write(JSON.stringify({ command: output.args.command, cwd: directory }))
        proc.stdin.end()
        text = await new Response(proc.stdout).text()
        code = await proc.exited
      } finally {
        clearTimeout(timer)
      }
      if (proc.killed) throw new Error("code-watch did not answer within " + TIMEOUT_MS / 1000 + " seconds")
      if (code !== 0) throw new Error("code-watch exited with code " + code)
      if (text.trim() === "") return
      const reply = JSON.parse(text)
      if (reply.decision === "allow") return
      if (reply.decision !== "deny") throw new Error("code-watch gave an answer the plugin does not know")
      reason = String(reply.reason || "code-watch denied this command")
    } catch (e) {
      if (FAIL_OPEN) return
      reason = UNCHECKED
    }
    throw new Error(reason)
  },
})
